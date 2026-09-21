package catalogrelease

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testGatewayID = "11111111-1111-4111-8111-111111111111"
	testTargetID  = "22222222-2222-4222-8222-222222222222"
)

func TestBuildProducesDeterministicVerifiedBundle(t *testing.T) {
	sourceName := "primary-cmdb"
	externalID := "db-001"
	catalog := Catalog{Version: 1, GatewayID: testGatewayID, Assets: []CatalogAsset{{
		TargetID: testTargetID, ExternalSource: &sourceName, ExternalID: &externalID, Ports: []int{6432, 5432},
	}}}
	source := TargetSource{Version: 1, Targets: []SourceTarget{{
		TargetID: testTargetID, ExternalSource: &sourceName, ExternalID: &externalID,
		Host: "db.internal", Ports: []int{5432, 6432},
	}}}
	first, err := Build(catalog, source)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	second, err := Build(catalog, source)
	if err != nil {
		t.Fatalf("Build second time: %v", err)
	}
	if string(first.Manifest) != string(second.Manifest) || first.Release.ReleaseID == "" {
		t.Fatalf("bundle is not deterministic: first=%s second=%s", first.Manifest, second.Manifest)
	}
	var targets SessionctlTargets
	if err := json.Unmarshal(first.Targets, &targets); err != nil {
		t.Fatalf("decode targets: %v", err)
	}
	if len(targets.Targets) != 1 || targets.Targets[0].Host != "db.internal" || targets.Targets[0].Ports[0] != 5432 {
		t.Fatalf("targets = %+v", targets)
	}
	digest := sha256.Sum256(first.Targets)
	if first.Release.Files.Targets.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("targets digest = %s", first.Release.Files.Targets.SHA256)
	}
}

func TestBuildRejectsIncompleteOrDriftingMappings(t *testing.T) {
	baseCatalog := Catalog{Version: 1, GatewayID: testGatewayID, Assets: []CatalogAsset{{TargetID: testTargetID, Ports: []int{5432}}}}
	tests := []struct {
		name   string
		source TargetSource
		match  string
	}{
		{"missing", TargetSource{Version: 1}, "no trusted target mapping"},
		{"port drift", TargetSource{Version: 1, Targets: []SourceTarget{{TargetID: testTargetID, Host: "10.0.0.1", Ports: []int{6432}}}}, "ports do not exactly match"},
		{"duplicate", TargetSource{Version: 1, Targets: []SourceTarget{{TargetID: testTargetID, Host: "10.0.0.1", Ports: []int{5432}}, {TargetID: testTargetID, Host: "10.0.0.2", Ports: []int{5432}}}}, "duplicates mapping"},
		{"extra", TargetSource{Version: 1, Targets: []SourceTarget{{TargetID: testTargetID, Host: "10.0.0.1", Ports: []int{5432}}, {TargetID: "33333333-3333-4333-8333-333333333333", Host: "10.0.0.2", Ports: []int{5432}}}}, "not present"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Build(baseCatalog, test.source)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("Build error = %v, want %q", err, test.match)
			}
		})
	}
}

func TestWriteUsesPrivateAtomicFiles(t *testing.T) {
	bundle, err := Build(
		Catalog{Version: 1, GatewayID: testGatewayID, Assets: []CatalogAsset{{TargetID: testTargetID, Ports: []int{5432}}}},
		TargetSource{Version: 1, Targets: []SourceTarget{{TargetID: testTargetID, Host: "10.0.0.1", Ports: []int{5432}}}},
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	output := filepath.Join(t.TempDir(), "release")
	if err := Write(output, bundle); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for _, name := range []string{"assets.json", "targets.json", "manifest.json"} {
		info, err := os.Stat(filepath.Join(output, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o", name, info.Mode().Perm())
		}
	}
}
