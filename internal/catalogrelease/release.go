package catalogrelease

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/srex-run/access-gateway/internal/id"
)

const maxInputBytes = 8 << 20

type Catalog struct {
	Version   int            `json:"version"`
	GatewayID string         `json:"gateway_id"`
	Assets    []CatalogAsset `json:"assets"`
}

type CatalogAsset struct {
	TargetID       string  `json:"target_id"`
	ExternalSource *string `json:"external_source,omitempty"`
	ExternalID     *string `json:"external_id,omitempty"`
	Ports          []int   `json:"ports"`
}

type TargetSource struct {
	Version int            `json:"version"`
	Targets []SourceTarget `json:"targets"`
}

type SourceTarget struct {
	TargetID       string  `json:"target_id,omitempty"`
	ExternalSource *string `json:"external_source,omitempty"`
	ExternalID     *string `json:"external_id,omitempty"`
	Host           string  `json:"host"`
	Ports          []int   `json:"ports"`
}

type AgentCatalog struct {
	Version int           `json:"version"`
	Assets  []AgentTarget `json:"assets"`
}

type AgentTarget struct {
	TargetID string `json:"target_id"`
	Ports    []int  `json:"ports"`
}

type SessionctlTargets struct {
	Version int                `json:"version"`
	Targets []SessionctlTarget `json:"targets"`
}

type SessionctlTarget struct {
	TargetID string `json:"target_id"`
	Host     string `json:"host"`
	Ports    []int  `json:"ports"`
}

type Manifest struct {
	Version   int           `json:"version"`
	GatewayID string        `json:"gateway_id"`
	ReleaseID string        `json:"release_id"`
	Files     ManifestFiles `json:"files"`
}

type ManifestFiles struct {
	Assets  ManifestFile `json:"assets.json"`
	Targets ManifestFile `json:"targets.json"`
}

type ManifestFile struct {
	SHA256 string `json:"sha256"`
}

type Bundle struct {
	Assets   []byte
	Targets  []byte
	Manifest []byte
	Release  Manifest
}

func Load(catalogPath, targetSourcePath string) (Catalog, TargetSource, error) {
	var catalog Catalog
	if err := decodeFile(catalogPath, &catalog); err != nil {
		return Catalog{}, TargetSource{}, fmt.Errorf("load gateway catalog: %w", err)
	}
	var source TargetSource
	if err := decodeFile(targetSourcePath, &source); err != nil {
		return Catalog{}, TargetSource{}, fmt.Errorf("load target source: %w", err)
	}
	return catalog, source, nil
}

func Build(catalog Catalog, source TargetSource) (Bundle, error) {
	if catalog.Version != 1 || source.Version != 1 {
		return Bundle{}, fmt.Errorf("catalog and target source versions must both be 1")
	}
	if !id.IsUUID(catalog.GatewayID) {
		return Bundle{}, fmt.Errorf("gateway_id must be a UUID")
	}

	byKey := make(map[string]SourceTarget, len(source.Targets))
	for index, target := range source.Targets {
		normalized, key, err := normalizeSourceTarget(target)
		if err != nil {
			return Bundle{}, fmt.Errorf("target source entry %d: %w", index, err)
		}
		if _, exists := byKey[key]; exists {
			return Bundle{}, fmt.Errorf("target source entry %d duplicates mapping %q", index, key)
		}
		byKey[key] = normalized
	}

	seenTargets := make(map[string]struct{}, len(catalog.Assets))
	usedMappings := make(map[string]struct{}, len(catalog.Assets))
	agentTargets := make([]AgentTarget, 0, len(catalog.Assets))
	sessionctlTargets := make([]SessionctlTarget, 0, len(catalog.Assets))
	for index, asset := range catalog.Assets {
		asset.TargetID = strings.TrimSpace(asset.TargetID)
		if !id.IsUUID(asset.TargetID) {
			return Bundle{}, fmt.Errorf("catalog asset %d has an invalid target_id", index)
		}
		if _, exists := seenTargets[asset.TargetID]; exists {
			return Bundle{}, fmt.Errorf("catalog contains duplicate target_id %q", asset.TargetID)
		}
		seenTargets[asset.TargetID] = struct{}{}
		ports, err := normalizePorts(asset.Ports)
		if err != nil {
			return Bundle{}, fmt.Errorf("catalog asset %q: %w", asset.TargetID, err)
		}
		key, err := catalogKey(asset)
		if err != nil {
			return Bundle{}, fmt.Errorf("catalog asset %q: %w", asset.TargetID, err)
		}
		mapping, exists := byKey[key]
		if !exists {
			return Bundle{}, fmt.Errorf("catalog asset %q has no trusted target mapping", asset.TargetID)
		}
		if mapping.TargetID != "" && mapping.TargetID != asset.TargetID {
			return Bundle{}, fmt.Errorf("catalog asset %q does not match mapped target_id %q", asset.TargetID, mapping.TargetID)
		}
		if !equalPorts(ports, mapping.Ports) {
			return Bundle{}, fmt.Errorf("catalog asset %q ports do not exactly match the trusted target mapping", asset.TargetID)
		}
		usedMappings[key] = struct{}{}
		agentTargets = append(agentTargets, AgentTarget{TargetID: asset.TargetID, Ports: ports})
		sessionctlTargets = append(sessionctlTargets, SessionctlTarget{TargetID: asset.TargetID, Host: mapping.Host, Ports: ports})
	}
	if len(usedMappings) != len(byKey) {
		return Bundle{}, fmt.Errorf("target source contains %d mapping(s) not present in the gateway catalog", len(byKey)-len(usedMappings))
	}

	sort.Slice(agentTargets, func(left, right int) bool { return agentTargets[left].TargetID < agentTargets[right].TargetID })
	sort.Slice(sessionctlTargets, func(left, right int) bool {
		return sessionctlTargets[left].TargetID < sessionctlTargets[right].TargetID
	})
	assetsJSON, err := marshalDocument(AgentCatalog{Version: 1, Assets: agentTargets})
	if err != nil {
		return Bundle{}, fmt.Errorf("encode agent catalog: %w", err)
	}
	targetsJSON, err := marshalDocument(SessionctlTargets{Version: 1, Targets: sessionctlTargets})
	if err != nil {
		return Bundle{}, fmt.Errorf("encode session controller targets: %w", err)
	}
	assetsHash := sha256Hex(assetsJSON)
	targetsHash := sha256Hex(targetsJSON)
	releaseHash := sha256.Sum256([]byte(catalog.GatewayID + "\n" + assetsHash + "\n" + targetsHash + "\n"))
	manifest := Manifest{
		Version: 1, GatewayID: catalog.GatewayID, ReleaseID: hex.EncodeToString(releaseHash[:]),
		Files: ManifestFiles{
			Assets:  ManifestFile{SHA256: assetsHash},
			Targets: ManifestFile{SHA256: targetsHash},
		},
	}
	manifestJSON, err := marshalDocument(manifest)
	if err != nil {
		return Bundle{}, fmt.Errorf("encode manifest: %w", err)
	}
	return Bundle{Assets: assetsJSON, Targets: targetsJSON, Manifest: manifestJSON, Release: manifest}, nil
}

func Write(outputDirectory string, bundle Bundle) error {
	outputDirectory = filepath.Clean(strings.TrimSpace(outputDirectory))
	if outputDirectory == "." || !filepath.IsAbs(outputDirectory) {
		return fmt.Errorf("output directory must be an absolute path")
	}
	if err := os.MkdirAll(outputDirectory, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	info, err := os.Lstat(outputDirectory)
	if err != nil {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("output directory must be a private, non-symlink directory")
	}
	for _, file := range []struct {
		name string
		data []byte
	}{{"assets.json", bundle.Assets}, {"targets.json", bundle.Targets}, {"manifest.json", bundle.Manifest}} {
		if err := writeAtomic(outputDirectory, file.name, file.data); err != nil {
			return err
		}
	}
	return nil
}

func decodeFile(path string, target any) error {
	file, err := os.Open(filepath.Clean(strings.TrimSpace(path)))
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxInputBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.InputOffset() > maxInputBytes {
		return fmt.Errorf("input exceeds %d bytes", maxInputBytes)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("input must contain exactly one JSON document")
	}
	return nil
}

func normalizeSourceTarget(target SourceTarget) (SourceTarget, string, error) {
	target.TargetID = strings.TrimSpace(target.TargetID)
	target.Host = strings.TrimSpace(target.Host)
	if target.TargetID != "" && !id.IsUUID(target.TargetID) {
		return SourceTarget{}, "", fmt.Errorf("target_id must be a UUID when provided")
	}
	if !validHost(target.Host) {
		return SourceTarget{}, "", fmt.Errorf("host is invalid")
	}
	ports, err := normalizePorts(target.Ports)
	if err != nil {
		return SourceTarget{}, "", err
	}
	target.Ports = ports
	key, err := sourceKey(target)
	if err != nil {
		return SourceTarget{}, "", err
	}
	return target, key, nil
}

func catalogKey(asset CatalogAsset) (string, error) {
	source, externalID, err := externalKeyParts(asset.ExternalSource, asset.ExternalID)
	if err != nil {
		return "", err
	}
	if source != "" {
		return "external:" + source + "\x00" + externalID, nil
	}
	return "target:" + asset.TargetID, nil
}

func sourceKey(target SourceTarget) (string, error) {
	source, externalID, err := externalKeyParts(target.ExternalSource, target.ExternalID)
	if err != nil {
		return "", err
	}
	if source != "" {
		return "external:" + source + "\x00" + externalID, nil
	}
	if target.TargetID == "" {
		return "", fmt.Errorf("mapping requires target_id or external_source/external_id")
	}
	return "target:" + target.TargetID, nil
}

func externalKeyParts(source, externalID *string) (string, string, error) {
	if (source == nil) != (externalID == nil) {
		return "", "", fmt.Errorf("external_source and external_id must be provided together")
	}
	if source == nil {
		return "", "", nil
	}
	normalizedSource := strings.TrimSpace(*source)
	normalizedID := strings.TrimSpace(*externalID)
	if normalizedSource == "" || normalizedID == "" || len(normalizedSource) > 64 || len(normalizedID) > 256 || strings.ContainsRune(normalizedSource, '\x00') || strings.ContainsRune(normalizedID, '\x00') {
		return "", "", fmt.Errorf("external_source or external_id is invalid")
	}
	return normalizedSource, normalizedID, nil
}

func normalizePorts(values []int) ([]int, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("ports must not be empty")
	}
	ports := append([]int(nil), values...)
	sort.Ints(ports)
	for index, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %d is outside 1-65535", port)
		}
		if index > 0 && ports[index-1] == port {
			return nil, fmt.Errorf("port %d is duplicated", port)
		}
	}
	return ports, nil
}

func equalPorts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validHost(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, " /\\\t\r\n") {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func marshalDocument(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(true)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func writeAtomic(directory, name string, data []byte) error {
	temporary, err := os.CreateTemp(directory, "."+name+"-*")
	if err != nil {
		return fmt.Errorf("create temporary %s: %w", name, err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("protect temporary %s: %w", name, err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary %s: %w", name, err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary %s: %w", name, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary %s: %w", name, err)
	}
	if err := os.Rename(temporaryName, filepath.Join(directory, name)); err != nil {
		return fmt.Errorf("publish %s: %w", name, err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open output directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync output directory: %w", err)
	}
	return nil
}
