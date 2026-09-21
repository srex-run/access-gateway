package sessionruntime

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestKubernetesDeploymentContainsOnlyAccessGateway(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl is not installed")
	}
	for _, directory := range []string{"kubernetes", "overlays/production"} {
		t.Run(directory, func(t *testing.T) {
			encoded, err := exec.Command("kubectl", "kustomize", filepath.Join("..", "..", "deploy", directory)).Output()
			if err != nil {
				t.Fatal(err)
			}
			decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(encoded), 4096)
			deployments := 0
			var controlImage, migrationImage, agentImage string
			for {
				var object unstructured.Unstructured
				if err := decoder.Decode(&object); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				if object.GetKind() == "StatefulSet" {
					t.Fatal("base contains a permanent session agent")
				}
				if object.GetKind() == "ConfigMap" && object.GetName() == "access-gateway-config" {
					agentImage, _, _ = unstructured.NestedString(object.Object, "data", "SESSION_AGENT_IMAGE")
				}
				if object.GetKind() == "Job" && object.GetName() == "access-gateway-migrate" {
					containers, _, _ := unstructured.NestedSlice(object.Object, "spec", "template", "spec", "containers")
					if len(containers) != 1 {
						t.Fatal("migration must run as a single one-shot container")
					}
					container := containers[0].(map[string]any)
					migrationImage, _, _ = unstructured.NestedString(container, "image")
					command, _, _ := unstructured.NestedStringSlice(container, "command")
					if strings.Join(command, " ") != "/usr/local/bin/migrate up" {
						t.Fatal("migration must override the application entrypoint")
					}
				}
				if object.GetKind() != "Deployment" {
					continue
				}
				deployments++
				if object.GetName() != "access-gateway" {
					t.Fatalf("unexpected Deployment: %s", object.GetName())
				}
				containers, _, _ := unstructured.NestedSlice(object.Object, "spec", "template", "spec", "containers")
				if len(containers) != 1 {
					t.Fatal("control plane and frontend must share one container")
				}
				controlImage, _, _ = unstructured.NestedString(containers[0].(map[string]any), "image")
			}
			if deployments != 1 {
				t.Fatalf("got %d Deployments", deployments)
			}
			if controlImage == "" || controlImage != migrationImage || controlImage != agentImage {
				t.Fatalf("application images differ: control=%q migration=%q agent=%q", controlImage, migrationImage, agentImage)
			}
		})
	}
}

func TestProductionPublicURLRendersMatchingIngressAndCallbacks(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl is not installed")
	}
	root := filepath.Join("..", "..")
	command := exec.Command("sh", "scripts/render-production-manifests.sh")
	command.Dir = root
	command.Env = append(os.Environ(),
		"PUBLIC_URL=https://access.example.test:8443/", "PUBLIC_HOST=obsolete.example.test",
		"ACCESS_GATEWAY_IMAGE_DIGEST=sha256:"+strings.Repeat("1", 64),
		"BUSYBOX_IMAGE_DIGEST=sha256:"+strings.Repeat("5", 64),
		"INGRESS_TLS_SECRET=platform-tls", "INGRESS_NAMESPACE=ingress-nginx", "MONITORING_NAMESPACE=monitoring",
		"POSTGRES_CIDR=10.20.30.40/32", "POSTGRES_PORT=5432", "TARGET_CIDR=10.10.0.0/16", "ACCESS_SOURCE_CIDR=10.40.0.0/16",
		"KUBERNETES_API_CIDR=10.96.0.1/32", "KUBERNETES_API_PORT=443", "EXTERNAL_HTTPS_CIDR=10.30.0.0/16",
		"SESSION_AGENT_NODE_NAME=worker-test", "ASSET_KEY_VERSION=key-test", "ADMIN_USER_IDS=ou_test_admin")
	encoded, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("render production: %v\n%s", err, encoded)
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(encoded), 4096)
	foundConfig, foundIngress := false, false
	for {
		var object unstructured.Unstructured
		if err := decoder.Decode(&object); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if object.GetKind() == "ConfigMap" && object.GetName() == "access-gateway-config" {
			foundConfig = true
			for _, key := range []string{"PUBLIC_URL", "SESSION_AGENT_CONTROL_PLANE_URL"} {
				value, _, _ := unstructured.NestedString(object.Object, "data", key)
				if value != "https://access.example.test:8443" {
					t.Fatalf("%s = %s", key, value)
				}
			}
		}
		if object.GetKind() == "Ingress" && object.GetName() == "access-gateway" {
			foundIngress = true
			rules, _, _ := unstructured.NestedSlice(object.Object, "spec", "rules")
			tls, _, _ := unstructured.NestedSlice(object.Object, "spec", "tls")
			if len(rules) != 1 || len(tls) != 1 || rules[0].(map[string]any)["host"] != "access.example.test" {
				t.Fatal("Ingress host diverged from PUBLIC_URL")
			}
			paths, _, _ := unstructured.NestedSlice(rules[0].(map[string]any), "http", "paths")
			for _, path := range paths {
				backend, _, _ := unstructured.NestedMap(path.(map[string]any), "backend", "service")
				port, _, _ := unstructured.NestedInt64(backend, "port", "number")
				if backend["name"] != "access-gateway" || port != 8080 {
					t.Fatal("all ingress routes must use the unified application service on port 8080")
				}
			}
			hosts := tls[0].(map[string]any)["hosts"].([]any)
			if len(hosts) != 1 || hosts[0] != "access.example.test" || object.GetAnnotations()["external-dns.alpha.kubernetes.io/hostname"] != "access.example.test" {
				t.Fatal("Ingress TLS or DNS diverged from PUBLIC_URL")
			}
		}
	}
	if !foundConfig || !foundIngress {
		t.Fatal("rendered platform config or ingress missing")
	}
}
