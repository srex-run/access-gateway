package sessionruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/id"
)

type dockerRoundTrip func(*http.Request) (*http.Response, error)

func (f dockerRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func dockerResponse(code int, body any) *http.Response {
	encoded, _ := json.Marshal(body)
	return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(encoded)), Header: make(http.Header)}
}

func TestDockerSessionContainerConfigurationAndLifecycle(t *testing.T) {
	d := newDockerDriver(HostOptions{Image: "registry.test/agent@sha256:" + strings.Repeat("1", 64), DockerStateDirectory: "/srv/access-gateway/sessions"}, id.New())
	record := hostRecord{SessionID: id.New()}
	containerID := strings.Repeat("a", 64)
	created, running := false, false
	var config dockerCreate
	d.client.Transport = dockerRoundTrip(func(r *http.Request) (*http.Response, error) {
		path := strings.TrimPrefix(r.URL.Path, dockerAPIVersion)
		switch {
		case path == "/info":
			return dockerResponse(200, map[string]any{"OSType": "linux", "OperatingSystem": "Debian", "SecurityOptions": []string{"name=seccomp"}}), nil
		case strings.HasPrefix(path, "/images/"):
			return dockerResponse(200, map[string]string{"Id": "sha256:" + strings.Repeat("1", 64)}), nil
		case path == "/containers/create" && r.Method == http.MethodPost:
			if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
				t.Fatal(err)
			}
			if r.URL.Query().Get("name") != d.name(record.SessionID) {
				t.Fatal("container name is not deterministic")
			}
			created = true
			return dockerResponse(201, map[string]string{"Id": containerID}), nil
		case path == "/containers/"+containerID+"/start" && r.Method == http.MethodPost:
			running = true
			return dockerResponse(204, nil), nil
		case strings.HasSuffix(path, "/json") && strings.HasPrefix(path, "/containers/"):
			if !created {
				return dockerResponse(404, nil), nil
			}
			return dockerResponse(200, map[string]any{"Id": containerID, "Config": map[string]any{"Labels": d.labels(record.SessionID)}, "State": map[string]bool{"Running": running}}), nil
		case path == "/containers/"+containerID+"/stop" && r.Method == http.MethodPost:
			if r.URL.Query().Get("t") != "10" {
				t.Fatal("container stop has no bounded grace period")
			}
			running = false
			return dockerResponse(204, nil), nil
		case path == "/containers/"+containerID && r.Method == http.MethodDelete:
			if running || r.URL.Query().Get("force") != "" {
				t.Fatal("container removed before termination")
			}
			created = false
			return dockerResponse(204, nil), nil
		default:
			t.Fatalf("unexpected Docker request: %s %s", r.Method, r.URL)
			return nil, nil
		}
	})
	ctx := context.Background()
	if err := d.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	var err error
	record.ResourceID, err = d.Start(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	if config.HostConfig.NetworkMode != "host" || config.HostConfig.RestartPolicy.Name != "no" || !config.HostConfig.ReadonlyRootfs || !config.HostConfig.Init ||
		len(config.HostConfig.CapDrop) != 1 || config.HostConfig.CapDrop[0] != "ALL" || len(config.HostConfig.SecurityOpt) != 1 || config.HostConfig.SecurityOpt[0] != "no-new-privileges:true" || config.User != fmt.Sprintf("%d:%d", os.Geteuid(), os.Getegid()) || config.HostConfig.PidsLimit <= 0 || config.HostConfig.Memory <= 0 {
		t.Fatalf("unsafe session container configuration: %+v", config.HostConfig)
	}
	if len(config.Env) != 2 || len(config.HostConfig.Mounts) != 2 || len(config.Cmd) != 5 || config.Cmd[0] != "session" {
		t.Fatal("container received unexpected environment, mounts or arguments")
	}
	grant, state := config.HostConfig.Mounts[0], config.HostConfig.Mounts[1]
	if !grant.ReadOnly || grant.Source != filepath.Join(d.options.DockerStateDirectory, "grants", record.SessionID+".json") ||
		state.Source != filepath.Join(d.options.DockerStateDirectory, "agents", record.SessionID) || state.ReadOnly {
		t.Fatal("container mounts are not scoped to its session")
	}
	if err := d.Remove(ctx, record); err == nil {
		t.Fatal("running container was removed")
	}
	if err := d.Stop(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := d.Remove(ctx, record); err != nil || created {
		t.Fatalf("container cleanup failed: %v", err)
	}
	if err := d.Remove(ctx, record); err != nil {
		t.Fatalf("container removal is not idempotent: %v", err)
	}
}

func TestDockerSessionRefusesForeignOrReplacedContainers(t *testing.T) {
	for _, mismatch := range []string{"controller", "session", "container-id"} {
		t.Run(mismatch, func(t *testing.T) {
			d := newDockerDriver(HostOptions{}, id.New())
			record := hostRecord{SessionID: id.New(), ResourceID: strings.Repeat("a", 64)}
			labels := d.labels(record.SessionID)
			containerID := record.ResourceID
			switch mismatch {
			case "controller":
				labels[dockerControllerLabel] = id.New()
			case "session":
				labels[sessionLabel] = id.New()
			case "container-id":
				containerID = strings.Repeat("b", 64)
			}
			d.client.Transport = dockerRoundTrip(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet {
					t.Fatal("foreign container was mutated")
				}
				return dockerResponse(200, map[string]any{"Id": containerID, "Config": map[string]any{"Labels": labels}, "State": map[string]bool{"Running": true}}), nil
			})
			if err := d.Stop(context.Background(), record); err == nil {
				t.Fatal("foreign container was stopped")
			}
			if err := d.Remove(context.Background(), record); err == nil {
				t.Fatal("foreign container was removed")
			}
		})
	}
}

func TestDockerSessionNeverRestartsAnExistingContainer(t *testing.T) {
	d := newDockerDriver(HostOptions{}, id.New())
	d.client.Transport = dockerRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != dockerAPIVersion+"/containers/create" {
			t.Fatal("existing container was restarted")
		}
		return dockerResponse(409, nil), nil
	})
	if _, err := d.Start(context.Background(), hostRecord{SessionID: id.New()}); err == nil {
		t.Fatal("container name conflict was ignored")
	}
}

func TestDockerSessionRejectsSourceIPRewritingRuntimes(t *testing.T) {
	for _, info := range []map[string]any{
		{"OSType": "windows"},
		{"OSType": "linux", "OperatingSystem": "Docker Desktop"},
		{"OSType": "linux", "SecurityOptions": []string{"name=rootless"}},
	} {
		d := newDockerDriver(HostOptions{}, id.New())
		d.client.Transport = dockerRoundTrip(func(*http.Request) (*http.Response, error) { return dockerResponse(200, info), nil })
		if err := d.Ready(context.Background()); err == nil {
			t.Fatalf("unsupported Docker networking accepted: %v", info)
		}
	}
}
