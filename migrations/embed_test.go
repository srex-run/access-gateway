package migrations

import (
	"io/fs"
	"strings"
	"testing"
)

func TestGooseFSAddsAuditFunctionStatementDirectives(t *testing.T) {
	original, err := FS.ReadFile(auditIntegrityMigration)
	if err != nil {
		t.Fatalf("read original migration: %v", err)
	}
	compatible, err := fs.ReadFile(GooseFS(), auditIntegrityMigration)
	if err != nil {
		t.Fatalf("read goose migration: %v", err)
	}

	if strings.Contains(string(original), "-- +goose StatementBegin") || strings.Contains(string(original), "-- +goose StatementEnd") {
		t.Fatal("historical migration must remain unchanged")
	}
	if count := strings.Count(string(compatible), "-- +goose StatementBegin"); count != 1 {
		t.Fatalf("StatementBegin count = %d, want 1", count)
	}
	if count := strings.Count(string(compatible), "-- +goose StatementEnd"); count != 1 {
		t.Fatalf("StatementEnd count = %d, want 1", count)
	}
	if info, err := fs.Stat(GooseFS(), auditIntegrityMigration); err != nil {
		t.Fatalf("stat goose migration: %v", err)
	} else if info.Size() != int64(len(compatible)) {
		t.Fatalf("migration size = %d, want %d", info.Size(), len(compatible))
	}
}

func TestGooseFSPreservesOtherMigrations(t *testing.T) {
	entries, err := FS.ReadDir(".")
	if err != nil {
		t.Fatalf("read migration directory: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == auditIntegrityMigration {
			continue
		}
		original, err := FS.ReadFile(entry.Name())
		if err != nil {
			t.Fatalf("read original %s: %v", entry.Name(), err)
		}
		compatible, err := fs.ReadFile(GooseFS(), entry.Name())
		if err != nil {
			t.Fatalf("read goose %s: %v", entry.Name(), err)
		}
		if string(compatible) != string(original) {
			t.Errorf("GooseFS changed %s", entry.Name())
		}
	}
}
