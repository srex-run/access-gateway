package sessionruntime

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

type composeConfig struct {
	Services map[string]struct {
		Image       string            `json:"image"`
		Entrypoint  []string          `json:"entrypoint"`
		Command     []string          `json:"command"`
		NetworkMode string            `json:"network_mode"`
		Environment map[string]string `json:"environment"`
		Volumes     []struct {
			Source string
			Target string
		}
	}
}

func TestDockerComposeContainsNoPermanentAgent(t *testing.T) {
	path := filepath.Join("..", "..", "docker-compose.yml")
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Services map[string]struct {
			Image       string            `json:"image"`
			Entrypoint  []string          `json:"entrypoint"`
			Command     []string          `json:"command"`
			NetworkMode string            `json:"network_mode"`
			Networks    map[string]any    `json:"networks"`
			Environment map[string]string `json:"environment"`
		}
	}
	jsonManifest, err := yaml.YAMLToJSONStrict(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(jsonManifest, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Services) != 5 || config.Services["access-gateway"].Environment["GATEWAY_RUNTIME"] != "docker" {
		t.Fatal("Compose must contain the application, PostgreSQL and three one-shot startup services")
	}
	for _, name := range []string{"prepare", "postgres", "migrate", "initialize", "access-gateway"} {
		if _, ok := config.Services[name]; !ok {
			t.Fatalf("Compose is missing startup service %s", name)
		}
	}
	if config.Services["migrate"].Image != config.Services["access-gateway"].Image || config.Services["initialize"].Image != config.Services["access-gateway"].Image || !strings.Contains(config.Services["access-gateway"].Environment["SESSION_AGENT_IMAGE"], "${ACCESS_GATEWAY_IMAGE:") {
		t.Fatal("control plane, migration, initialization and session agents must share one image")
	}
	if strings.Join(config.Services["migrate"].Entrypoint, " ") != "/usr/local/bin/migrate" || strings.Join(config.Services["migrate"].Command, " ") != "up" {
		t.Fatal("migration must override the application entrypoint")
	}
	if strings.Join(config.Services["initialize"].Entrypoint, " ") != "/usr/local/bin/account" || strings.Join(config.Services["initialize"].Command, " ") != "bootstrap" {
		t.Fatal("initialization must run the idempotent account bootstrap")
	}
	if config.Services["access-gateway"].NetworkMode != "host" {
		t.Fatal("control plane is outside the session host network")
	}
	for _, name := range []string{"postgres", "migrate", "initialize"} {
		if _, ok := config.Services[name].Networks["database"]; !ok || config.Services[name].NetworkMode != "" {
			t.Fatalf("%s must use the private database network", name)
		}
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker CLI is not installed; static Compose contract passed")
	}
	// migrate, initialize and access-gateway declare env_file: .env, which
	// Compose stats even under --no-env-resolution, and .env is never committed.
	// Render from a throwaway copy of the manifest next to the published
	// example, the way scripts/compose-startup.test.mjs does, so a clean
	// checkout renders the same model a host does and the project directory
	// stays the manifest's own directory.
	example, err := os.ReadFile(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(t.TempDir(), "access-gateway-compose")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "docker-compose.yml"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".env"), example, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("docker", "compose", "--env-file", filepath.Join(workspace, ".env"),
		"config", "--no-env-resolution", "--format", "json")
	command.Dir = workspace
	command.Env = append(os.Environ(),
		"ACCESS_GATEWAY_IMAGE=registry.test/api@sha256:"+strings.Repeat("1", 64),
		"ACCESS_GATEWAY_SECRETS_HOST_PATH=/srv/control-secrets", "SESSION_AGENT_STATE_HOST_PATH=/srv/session-state",
		"PUBLIC_URL=https://access.example.test:8443", "DOCKER_SOCKET_GID=999", "DOCKER_SOCKET_HOST_PATH=/var/run/docker.sock",
		"SESSION_AGENT_CONTROL_PLANE_URL=", "SESSION_AGENT_ALLOW_AUDIT_HTTP=", "ACCESS_GATEWAY_API_PORT=18080")
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	encoded, err = command.Output()
	if err != nil {
		t.Fatalf("Docker Compose rendering failed: %v: %s", err, strings.TrimSpace(diagnostics.String()))
	}
	var rendered composeConfig
	if err := json.Unmarshal(encoded, &rendered); err != nil {
		t.Fatal(err)
	}
	api := rendered.Services["access-gateway"]
	if api.Image != rendered.Services["migrate"].Image || api.Image != rendered.Services["initialize"].Image || api.Environment["SESSION_AGENT_IMAGE"] != api.Image {
		t.Fatal("rendered workloads must share one application image")
	}
	if api.Environment["PUBLIC_URL"] != "https://access.example.test:8443" {
		t.Fatal("Compose dropped the configured public origin")
	}
	if api.Environment["SESSION_AGENT_CONTROL_PLANE_URL"] != "http://127.0.0.1:18080" || api.Environment["SESSION_AGENT_DOCKER_STATE_DIR"] != "/srv/session-state" || api.Environment["HTTP_ADDR"] != "127.0.0.1:18080" {
		t.Fatal("Compose interpolation changed the host session contract")
	}
	for _, service := range []string{"migrate", "initialize"} {
		for _, mount := range rendered.Services[service].Volumes {
			if mount.Target == "/var/run/docker.sock" || mount.Target == "/var/lib/access-gateway/sessions" {
				t.Fatalf("%s received session controller mounts", service)
			}
		}
	}
}
