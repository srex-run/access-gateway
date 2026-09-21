package migrations

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Versions describes the schema required by this binary without initializing
// Goose's version table or changing its process-global configuration.
func Versions() ([]int64, error) {
	entries, err := FS.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migration versions: %w", err)
	}
	versions := []int64{}
	seen := map[int64]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		version, err := strconv.ParseInt(prefix, 10, 64)
		if !ok || err != nil || version < 1 || seen[version] {
			return nil, fmt.Errorf("invalid or duplicate migration version: %s", entry.Name())
		}
		seen[version] = true
		versions = append(versions, version)
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("no embedded migrations found")
	}
	slices.Sort(versions)
	return versions, nil
}
