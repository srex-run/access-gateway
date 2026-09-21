package migrations

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
)

// FS is embedded for migration jobs and integration tests; serving never mutates schema.
//
//go:embed *.sql
var FS embed.FS

const (
	auditIntegrityMigration = "00003_audit_integrity.sql"
	auditFunctionStart      = "CREATE OR REPLACE FUNCTION prevent_audit_event_mutation()"
	auditFunctionEnd        = "$$;\n\nCREATE TRIGGER audit_events_append_only"
)

// GooseFS exposes the immutable migration history with parser directives that
// older migrations need when Goose splits PostgreSQL function bodies.
func GooseFS() fs.FS {
	return gooseCompatibilityFS{FS: FS}
}

type gooseCompatibilityFS struct {
	fs.FS
}

func (compat gooseCompatibilityFS) Open(name string) (fs.File, error) {
	if name != auditIntegrityMigration {
		return compat.FS.Open(name)
	}

	content, err := fs.ReadFile(compat.FS, name)
	if err != nil {
		return nil, err
	}
	content, err = addAuditFunctionDirectives(content)
	if err != nil {
		return nil, fmt.Errorf("prepare %s for goose: %w", name, err)
	}
	info, err := fs.Stat(compat.FS, name)
	if err != nil {
		return nil, err
	}
	return &memoryFile{
		Reader: bytes.NewReader(content),
		info:   sizedFileInfo{FileInfo: info, size: int64(len(content))},
	}, nil
}

func addAuditFunctionDirectives(content []byte) ([]byte, error) {
	start := []byte(auditFunctionStart)
	end := []byte(auditFunctionEnd)
	if bytes.Count(content, start) != 1 || bytes.Count(content, end) != 1 {
		return nil, fmt.Errorf("expected audit function markers exactly once")
	}
	content = bytes.Replace(content, start, append([]byte("-- +goose StatementBegin\n"), start...), 1)
	statementEnd := []byte("$$;\n-- +goose StatementEnd\n\nCREATE TRIGGER audit_events_append_only")
	return bytes.Replace(content, end, statementEnd, 1), nil
}

type memoryFile struct {
	*bytes.Reader
	info fs.FileInfo
}

func (file *memoryFile) Close() error { return nil }

func (file *memoryFile) Stat() (fs.FileInfo, error) { return file.info, nil }

type sizedFileInfo struct {
	fs.FileInfo
	size int64
}

func (info sizedFileInfo) Size() int64 { return info.size }
