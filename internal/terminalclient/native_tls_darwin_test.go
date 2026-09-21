package terminalclient

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Unlike MySQL, openssl reports the underlying file/PEM error instead of
// replacing every CA-loading failure with SSL_CTX_set_default_verify_paths.
// This probe needs no listener, database, account or password.
func TestMacClientPrivateCAFile(t *testing.T) {
	if os.Getenv("RUN_TERMINAL_SANDBOX_TESTS") != "1" {
		t.Skip("requires OpenSSL and RUN_TERMINAL_SANDBOX_TESTS=1")
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatal(err)
	}
	// Session agents do not inherit TMPDIR, so os.TempDir uses /tmp on macOS.
	directory, err := os.MkdirTemp("/tmp", "gateway-terminal-ca-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _, _ := nativeTestTLS(t)
	if err := os.WriteFile(filepath.Join(directory, "ca.pem"), []byte(certificate), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(directory, trustDirectory), 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(directory, "client.sb")
	if err := os.WriteFile(profile, []byte(darwinProfile(openssl, directory, "1", "")), 0600); err != nil {
		t.Fatal(err)
	}
	for _, sample := range []struct {
		name, path string
		isolated   bool
	}{
		{"control", directory, false},
		{"isolated_tmp_alias", directory, true},
		{"isolated_canonical_path", canonical, true},
	} {
		t.Run(sample.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ca := filepath.Join(sample.path, "ca.pem")
			command := exec.CommandContext(ctx, openssl, "verify", "-CAfile", ca, ca)
			if sample.isolated {
				command = exec.CommandContext(ctx, "/usr/bin/sandbox-exec", "-f", profile, openssl, "verify", "-CAfile", ca, ca)
			}
			command.Dir = sample.path
			command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + sample.path, "TMPDIR=" + sample.path,
				"SSL_CERT_FILE=" + ca, "SSL_CERT_DIR=" + filepath.Join(sample.path, trustDirectory)}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("OpenSSL CA load: %v\n%s", err, output)
			}
		})
	}
}
