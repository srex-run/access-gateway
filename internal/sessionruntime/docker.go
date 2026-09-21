package sessionruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const dockerControllerLabel = "access-gateway.srex.run/controller-id"
const dockerAPIVersion = "/v1.45"

type dockerDriver struct {
	client     *http.Client
	options    HostOptions
	instanceID string
}

type dockerContainer struct {
	ID    string `json:"Id"`
	Name  string
	State struct {
		Running bool
		Paused  bool
	}
	Config struct {
		Labels map[string]string
	}
}

type dockerCreate struct {
	Image      string
	User       string
	Entrypoint []string
	Cmd        []string
	Env        []string
	Labels     map[string]string
	HostConfig dockerHostConfig
}

type dockerHostConfig struct {
	NetworkMode    string
	ReadonlyRootfs bool
	Init           bool
	CapDrop        []string
	SecurityOpt    []string
	PidsLimit      int64
	Memory         int64
	NanoCpus       int64
	RestartPolicy  struct{ Name string }
	Mounts         []dockerMount
	Tmpfs          map[string]string
	LogConfig      struct {
		Type   string
		Config map[string]string
	}
}

type dockerMount struct {
	Type     string
	Source   string
	Target   string
	ReadOnly bool
}

func validateDockerOptions(options HostOptions) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("Docker session runtime requires a Linux control plane sharing the Docker host network")
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("Docker session controller and agents must run as a non-root user")
	}
	if !filepath.IsAbs(options.DockerSocket) || !filepath.IsAbs(options.DockerStateDirectory) ||
		strings.TrimSpace(options.Image) == "" || strings.ContainsAny(options.Image, " \t\r\n") {
		return fmt.Errorf("Docker runtime requires an absolute engine socket path, host state directory and session agent image")
	}
	return nil
}

func newDockerDriver(options HostOptions, instanceID string) *dockerDriver {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", options.DockerSocket)
	}}
	return &dockerDriver{options: options, instanceID: instanceID, client: &http.Client{
		Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (d *dockerDriver) Ready(ctx context.Context) error {
	var info struct {
		OSType          string
		OperatingSystem string
		SecurityOptions []string
	}
	if _, err := d.request(ctx, http.MethodGet, "/info", nil, &info, http.StatusOK); err != nil {
		return fmt.Errorf("Docker Engine 26+ is unavailable: %w", err)
	}
	if info.OSType != "linux" || strings.Contains(strings.ToLower(info.OperatingSystem), "docker desktop") {
		return fmt.Errorf("session containers require native Linux host networking to preserve source IPs")
	}
	for _, option := range info.SecurityOptions {
		if strings.Contains(option, "rootless") {
			return fmt.Errorf("rootless Docker networking cannot provide the required host source-IP boundary")
		}
	}
	var image struct{ ID string }
	if _, err := d.request(ctx, http.MethodGet, "/images/"+url.PathEscape(d.options.Image)+"/json", nil, &image, http.StatusOK); err != nil {
		return fmt.Errorf("session agent image must be loaded on the Docker host: %w", err)
	}
	return nil
}

func (d *dockerDriver) Start(ctx context.Context, record hostRecord) (string, error) {
	config := dockerCreate{
		Image: d.options.Image, User: fmt.Sprintf("%d:%d", os.Geteuid(), os.Getegid()),
		Entrypoint: []string{"/usr/local/bin/gateway-agent"},
		Cmd:        []string{"session", "--config", "/run/session/grant/session.json", "--state-dir", "/run/session/private"},
		Env:        []string{"LANG=C", "TZ=UTC"}, Labels: d.labels(record.SessionID),
		HostConfig: dockerHostConfig{
			NetworkMode: "host", ReadonlyRootfs: true, Init: true,
			CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
			PidsLimit: 64, Memory: 128 << 20, NanoCpus: 1_000_000_000,
			Mounts: []dockerMount{
				{Type: "bind", Source: filepath.Join(d.options.DockerStateDirectory, "grants", record.SessionID+".json"), Target: "/run/session/grant/session.json", ReadOnly: true},
				{Type: "bind", Source: filepath.Join(d.options.DockerStateDirectory, "agents", record.SessionID), Target: "/run/session/private"},
			},
			Tmpfs: map[string]string{"/tmp": "rw,noexec,nosuid,size=8388608,mode=1777"},
		},
	}
	config.HostConfig.RestartPolicy.Name = "no"
	if record.ConnectionMode == "audit" {
		// Native interactive clients, particularly mongosh, need more memory
		// than a byte-forwarding worker. Retain the existing CPU/capability limits.
		config.HostConfig.Memory = 512 << 20
		config.HostConfig.PidsLimit = 128
		config.HostConfig.Tmpfs["/tmp"] = "rw,noexec,nosuid,size=33554432,mode=1777"
	}
	config.HostConfig.LogConfig.Type = "json-file"
	config.HostConfig.LogConfig.Config = map[string]string{"max-size": "10m", "max-file": "2"}
	var created struct {
		ID string `json:"Id"`
	}
	// An existing name is never started. It may be a previous, stopped workload
	// from an uncertain request; reconciliation will inspect its ownership.
	if _, err := d.request(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(d.name(record.SessionID)), config, &created, http.StatusCreated); err != nil {
		return "", err
	}
	if !validContainerID(created.ID) {
		return "", fmt.Errorf("Docker returned an invalid session container ID")
	}
	if _, err := d.request(ctx, http.MethodPost, "/containers/"+created.ID+"/start", nil, nil, http.StatusNoContent); err != nil {
		return "", err
	}
	return created.ID, nil
}

func (d *dockerDriver) inspect(ctx context.Context, record hostRecord) (dockerContainer, bool, error) {
	reference := d.name(record.SessionID)
	if record.ResourceID != "" {
		if !validContainerID(record.ResourceID) {
			return dockerContainer{}, false, fmt.Errorf("invalid recorded session container ID")
		}
		reference = record.ResourceID
	}
	var container dockerContainer
	status, err := d.request(ctx, http.MethodGet, "/containers/"+reference+"/json", nil, &container, http.StatusOK, http.StatusNotFound)
	if err != nil || status == http.StatusNotFound {
		return container, false, err
	}
	if !validContainerID(container.ID) || (record.ResourceID != "" && record.ResourceID != container.ID) {
		return container, false, fmt.Errorf("session container identity changed")
	}
	for key, value := range d.labels(record.SessionID) {
		if container.Config.Labels[key] != value {
			return container, false, fmt.Errorf("refuse to manage an unowned session container")
		}
	}
	return container, true, nil
}

func (d *dockerDriver) Inspect(ctx context.Context, record hostRecord) (hostResource, error) {
	container, exists, err := d.inspect(ctx, record)
	return hostResource{ID: container.ID, Exists: exists, Running: container.State.Running || container.State.Paused}, err
}

func (d *dockerDriver) Stop(ctx context.Context, record hostRecord) error {
	container, exists, err := d.inspect(ctx, record)
	if err != nil || !exists {
		return err
	}
	if container.State.Paused {
		if _, err := d.request(ctx, http.MethodPost, "/containers/"+container.ID+"/unpause", nil, nil, http.StatusNoContent); err != nil {
			return err
		}
	}
	if container.State.Running || container.State.Paused {
		if _, err := d.request(ctx, http.MethodPost, "/containers/"+container.ID+"/stop?t=10", nil, nil, http.StatusNoContent, http.StatusNotModified, http.StatusNotFound); err != nil {
			return err
		}
	}
	return pollHost(ctx, 100*time.Millisecond, func() (bool, error) {
		resource, err := d.Inspect(ctx, record)
		return !resource.Running, err
	})
}

func (d *dockerDriver) Remove(ctx context.Context, record hostRecord) error {
	container, exists, err := d.inspect(ctx, record)
	if err != nil || !exists {
		return err
	}
	if container.State.Running || container.State.Paused {
		return fmt.Errorf("refuse to delete a running session container")
	}
	_, err = d.request(ctx, http.MethodDelete, "/containers/"+container.ID+"?v=true", nil, nil, http.StatusNoContent, http.StatusNotFound)
	return err
}

func (d *dockerDriver) request(ctx context.Context, method, path string, input, output any, accepted ...int) (int, error) {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://docker"+dockerAPIVersion+path, body)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := d.client.Do(request)
	if err != nil {
		return 0, fmt.Errorf("Docker Engine request failed: %w", err)
	}
	defer response.Body.Close()
	for _, status := range accepted {
		if response.StatusCode == status {
			if output != nil && status != http.StatusNotFound {
				if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output); err != nil {
					return status, fmt.Errorf("decode Docker Engine response: %w", err)
				}
			}
			return status, nil
		}
	}
	return response.StatusCode, fmt.Errorf("Docker Engine returned HTTP %d", response.StatusCode)
}

func (d *dockerDriver) name(sessionID string) string {
	return "access-gateway-" + d.instanceID + "-" + sessionID
}

func (d *dockerDriver) labels(sessionID string) map[string]string {
	return map[string]string{managedLabel: managedValue, sessionLabel: sessionID, appLabel: appValue, dockerControllerLabel: d.instanceID}
}

func validContainerID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}
