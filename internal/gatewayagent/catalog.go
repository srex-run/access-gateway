package gatewayagent

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/srex-run/access-gateway/internal/id"
)

const maxCatalogFileBytes = 1 << 20

type TargetCatalog interface {
	Authorize(targetID string, targetPort int) error
}

type AssetCatalogEntry struct {
	TargetID string `json:"target_id"`
	Ports    []int  `json:"ports"`
}

type AssetCatalog struct {
	allowed map[string]map[int]struct{}
}

type assetCatalogDocument struct {
	Version int                 `json:"version"`
	Assets  []AssetCatalogEntry `json:"assets"`
}

func LoadAssetCatalog(path string) (*AssetCatalog, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("gateway asset catalog path must be absolute: %w", ErrInvalidInput)
	}
	if err := validateProtectedDirectory(filepath.Dir(path), "gateway asset catalog"); err != nil {
		return nil, err
	}
	file, info, err := openRegularFile(path, "gateway asset catalog")
	if err != nil {
		return nil, fmt.Errorf("open gateway asset catalog: %w", err)
	}
	defer file.Close()
	if info.Size() > maxCatalogFileBytes {
		return nil, fmt.Errorf("gateway asset catalog exceeds %d bytes: %w", maxCatalogFileBytes, ErrInvalidInput)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("gateway asset catalog must not be group or world writable: %w", ErrInvalidInput)
	}

	decoder := json.NewDecoder(io.LimitReader(file, maxCatalogFileBytes+1))
	decoder.DisallowUnknownFields()
	var document assetCatalogDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode gateway asset catalog: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode gateway asset catalog: %w", err)
	}
	if document.Version != 1 {
		return nil, fmt.Errorf("unsupported gateway asset catalog version %d", document.Version)
	}
	return NewAssetCatalog(document.Assets)
}

func NewAssetCatalog(entries []AssetCatalogEntry) (*AssetCatalog, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("gateway asset catalog is empty: %w", ErrInvalidInput)
	}
	allowed := make(map[string]map[int]struct{}, len(entries))
	for _, entry := range entries {
		if !id.IsUUID(entry.TargetID) || len(entry.Ports) == 0 {
			return nil, fmt.Errorf("gateway asset catalog entry is invalid: %w", ErrInvalidInput)
		}
		if _, exists := allowed[entry.TargetID]; exists {
			return nil, fmt.Errorf("gateway asset catalog contains duplicate target %q: %w", entry.TargetID, ErrInvalidInput)
		}
		ports := make(map[int]struct{}, len(entry.Ports))
		for _, port := range entry.Ports {
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("gateway asset catalog port is invalid: %w", ErrInvalidInput)
			}
			if _, exists := ports[port]; exists {
				return nil, fmt.Errorf("gateway asset catalog contains duplicate port for target %q: %w", entry.TargetID, ErrInvalidInput)
			}
			ports[port] = struct{}{}
		}
		allowed[entry.TargetID] = ports
	}
	return &AssetCatalog{allowed: allowed}, nil
}

func (c *AssetCatalog) Authorize(targetID string, targetPort int) error {
	if c == nil {
		return fmt.Errorf("gateway asset catalog is unavailable: %w", ErrTargetNotAllowed)
	}
	ports, exists := c.allowed[targetID]
	if !exists {
		return fmt.Errorf("target is absent from the local catalog: %w", ErrTargetNotAllowed)
	}
	if _, exists := ports[targetPort]; !exists {
		return fmt.Errorf("target port is absent from the local catalog: %w", ErrTargetNotAllowed)
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
