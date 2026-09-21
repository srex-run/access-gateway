package gatewayagent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/srex-run/access-gateway/internal/id"
)

type TargetResolver interface {
	Resolve(targetID string, targetPort int) (string, error)
}

type TargetMapEntry struct {
	TargetID string `json:"target_id"`
	Host     string `json:"host"`
	Ports    []int  `json:"ports"`
}

type targetMapDocument struct {
	Version int              `json:"version"`
	Targets []TargetMapEntry `json:"targets"`
}

type StaticTargetResolver struct {
	targets map[string]resolvedTarget
}

type resolvedTarget struct {
	host  string
	ports map[int]struct{}
}

func LoadTargetResolver(path string) (*StaticTargetResolver, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	encoded, info, err := readProtectedFile(path, "gateway target map", maxCatalogFileBytes)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("gateway target map must not be group or world writable: %w", ErrInvalidInput)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var document targetMapDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode gateway target map: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode gateway target map: %w", err)
	}
	if document.Version != 1 {
		return nil, fmt.Errorf("unsupported gateway target map version %d", document.Version)
	}
	return NewStaticTargetResolver(document.Targets)
}

func NewStaticTargetResolver(entries []TargetMapEntry) (*StaticTargetResolver, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("gateway target map is empty: %w", ErrInvalidInput)
	}
	targets := make(map[string]resolvedTarget, len(entries))
	for _, entry := range entries {
		entry.Host = strings.TrimSpace(entry.Host)
		if !id.IsUUID(entry.TargetID) || !validTargetHost(entry.Host) || len(entry.Ports) == 0 {
			return nil, fmt.Errorf("gateway target map entry is invalid: %w", ErrInvalidInput)
		}
		if _, exists := targets[entry.TargetID]; exists {
			return nil, fmt.Errorf("gateway target map contains duplicate target %q: %w", entry.TargetID, ErrInvalidInput)
		}
		ports := make(map[int]struct{}, len(entry.Ports))
		for _, port := range entry.Ports {
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("gateway target map contains an invalid port: %w", ErrInvalidInput)
			}
			if _, exists := ports[port]; exists {
				return nil, fmt.Errorf("gateway target map contains a duplicate port: %w", ErrInvalidInput)
			}
			ports[port] = struct{}{}
		}
		targets[entry.TargetID] = resolvedTarget{host: entry.Host, ports: ports}
	}
	return &StaticTargetResolver{targets: targets}, nil
}

func (r *StaticTargetResolver) Resolve(targetID string, targetPort int) (string, error) {
	if r == nil {
		return "", fmt.Errorf("gateway target resolver is unavailable: %w", ErrTargetNotAllowed)
	}
	target, exists := r.targets[targetID]
	if !exists {
		return "", fmt.Errorf("target is absent from the protected target map: %w", ErrTargetNotAllowed)
	}
	if _, exists := target.ports[targetPort]; !exists {
		return "", fmt.Errorf("target port is absent from the protected target map: %w", ErrTargetNotAllowed)
	}
	return net.JoinHostPort(target.host, fmt.Sprintf("%d", targetPort)), nil
}

func validTargetHost(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/\\?#@[]%:") {
		if address, err := netip.ParseAddr(value); err == nil {
			return !address.IsUnspecified() && !address.IsMulticast()
		}
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}
