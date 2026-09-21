//go:build darwin || linux

package terminalclient

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientDirectoryResolvesTemporaryRootSymlinks(t *testing.T) {
	root := t.TempDir()
	realRoot := filepath.Join(root, "real")
	if err := os.Mkdir(realRoot, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(realRoot, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", alias)
	directory, err := newClientDirectory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || directory != canonical || !filepath.IsAbs(directory) {
		t.Fatalf("client directory is not canonical: %q, %v", directory, err)
	}
	if info, err := os.Stat(directory); err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("client directory is not private")
	}
}

func TestClientTLSMaterialReportsOnlySafeCauses(t *testing.T) {
	certificate, key, _ := nativeTestTLS(t)
	_, otherKey, _ := nativeTestTLS(t)
	for _, sample := range []struct {
		name, ca, identity, file, problem string
	}{
		{name: "valid", ca: certificate, identity: certificate + key},
		{name: "CA missing", file: "ca", problem: "not_found"},
		{name: "CA malformed", ca: "secret=must-not-be-logged", file: "ca", problem: "invalid_pem"},
		{name: "identity missing", ca: certificate, file: "identity", problem: "not_found"},
		{name: "identity malformed", ca: certificate, identity: "key=must-not-be-logged", file: "identity", problem: "invalid_pem"},
		{name: "identity key mismatch", ca: certificate, identity: certificate + otherKey, file: "identity", problem: "invalid_pem"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			directory := t.TempDir()
			for name, data := range map[string]string{"ca.pem": sample.ca, "client.pem": sample.identity} {
				if data != "" {
					if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			err := checkTLSMaterial(directory, true)
			if sample.file == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || err.File != sample.file || err.Problem != sample.problem {
				t.Fatalf("unexpected TLS material diagnostic: %v", err)
			}
			if strings.Contains(err.Error(), "must-not-be-logged") || strings.Contains(err.Error(), directory) || strings.Contains(err.Error(), "BEGIN") {
				t.Fatal("TLS material diagnostic includes private data")
			}
		})
	}
}

func TestClientTLSMaterialRejectsUnreadableCA(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read files regardless of their permission bits")
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "ca.pem"), []byte("must-not-be-logged"), 0000); err != nil {
		t.Fatal(err)
	}
	err := checkTLSMaterial(directory, true)
	if err == nil || err.File != "ca" || err.Problem != "permission_denied" {
		t.Fatalf("unreadable CA did not report the permission failure: %v", err)
	}
}

func TestClientTLSMaterialReportRejectsUnrecognizedData(t *testing.T) {
	for _, payload := range []string{"", "not JSON", `{"file":"password=secret","problem":"invalid_pem"}`, `{"file":"ca","problem":"key=secret"}`} {
		if err := readTLSMaterialError(strings.NewReader(payload)); err != nil {
			t.Fatal("accepted unrecognized helper diagnostic")
		}
	}
	err := readTLSMaterialError(strings.NewReader(`{"file":"ca","problem":"permission_denied"}`))
	var materialError *TLSMaterialError
	if !errors.As(err, &materialError) || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("helper diagnostic was lost: %v", err)
	}
}
