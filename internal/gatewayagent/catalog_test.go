package gatewayagent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAssetCatalogAuthorizesOnlyListedTargetPorts(t *testing.T) {
	catalog, err := NewAssetCatalog([]AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432, 5433}}})
	if err != nil {
		t.Fatalf("NewAssetCatalog: %v", err)
	}
	if err := catalog.Authorize(testGatewayTargetID, 5432); err != nil {
		t.Fatalf("Authorize listed target: %v", err)
	}
	for _, candidate := range []struct {
		target string
		port   int
	}{{testGatewayTargetID, 22}, {testOtherTargetID, 5432}} {
		if err := catalog.Authorize(candidate.target, candidate.port); !errors.Is(err, ErrTargetNotAllowed) {
			t.Fatalf("Authorize(%q, %d) error = %v", candidate.target, candidate.port, err)
		}
	}
}

func TestLoadAssetCatalogRejectsWritableUnknownAndTrailingContent(t *testing.T) {
	directory := t.TempDir()
	valid := `{"version":1,"assets":[{"target_id":"` + testGatewayTargetID + `","ports":[5432]}]}`
	path := filepath.Join(directory, "assets.json")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatalf("write catalog: %v", err)
	}
	catalog, err := LoadAssetCatalog(path)
	if err != nil || catalog.Authorize(testGatewayTargetID, 5432) != nil {
		t.Fatalf("LoadAssetCatalog valid file: catalog=%v err=%v", catalog, err)
	}

	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatalf("chmod catalog: %v", err)
	}
	if _, err := LoadAssetCatalog(path); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("writable catalog error = %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("restore catalog mode: %v", err)
	}

	for name, value := range map[string]string{
		"unknown":  strings.TrimSuffix(valid, "}") + `,"unexpected":true}`,
		"trailing": valid + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				t.Fatalf("write invalid catalog: %v", err)
			}
			if _, err := LoadAssetCatalog(path); err == nil {
				t.Fatal("invalid catalog was accepted")
			}
		})
	}
}

func TestNewAssetCatalogRejectsDuplicateAndMalformedEntries(t *testing.T) {
	for name, entries := range map[string][]AssetCatalogEntry{
		"empty":          nil,
		"invalid id":     {{TargetID: "not-an-id", Ports: []int{5432}}},
		"empty ports":    {{TargetID: testGatewayTargetID}},
		"invalid port":   {{TargetID: testGatewayTargetID, Ports: []int{70000}}},
		"duplicate port": {{TargetID: testGatewayTargetID, Ports: []int{5432, 5432}}},
		"duplicate target": {
			{TargetID: testGatewayTargetID, Ports: []int{5432}},
			{TargetID: testGatewayTargetID, Ports: []int{5433}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewAssetCatalog(entries); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("NewAssetCatalog error = %v", err)
			}
		})
	}
}
