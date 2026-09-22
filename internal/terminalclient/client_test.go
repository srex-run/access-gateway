package terminalclient

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/srex-run/access-gateway/internal/terminal"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "terminal-client" {
		os.Exit(ChildMain())
	}
	if len(os.Args) == 2 && os.Args[1] == "sandbox-probe" {
		os.Exit(sandboxProbe())
	}
	os.Exit(m.Run())
}

func TestClientExitDistinguishesCleanupFromCrash(t *testing.T) {
	killed := exec.Command("/bin/sh", "-c", "kill -KILL $$").Run()
	failed := exec.Command("/bin/sh", "-c", "exit 7").Run()
	for _, sample := range []struct {
		name                string
		wait, output, setup error
		cause               error
		closed              bool
	}{
		{"user close kills client", killed, nil, nil, terminal.ErrTerminalClosed, true},
		{"expiry closes PTY", killed, os.ErrClosed, nil, terminal.ErrSessionExpired, true},
		{"browser close already acknowledged", killed, websocket.ErrCloseSent, nil, terminal.ErrTerminalClosed, true},
		{"session stop", nil, nil, nil, terminal.ErrSessionClosed, true},
		{"actual client error", failed, nil, nil, terminal.ErrSessionClosed, false},
		{"unexpected kill", killed, nil, nil, nil, false},
		{"audit failure while closing", killed, errors.New("audit failed"), nil, terminal.ErrSessionClosed, false},
		{"TLS setup failure while closing", killed, nil, &TLSMaterialError{File: "ca", Problem: "not_found"}, terminal.ErrSessionClosed, false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			err := clientExitError(sample.wait, sample.output, sample.setup, sample.cause)
			if (terminal.CloseReason(err) != "") != sample.closed {
				t.Fatalf("wrong exit classification: %v", err)
			}
		})
	}
}

func TestNativeClientArgumentsDoNotContainPasswords(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mariadb", "mysql", "psql", "redis-cli", "mongosh", "bash"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	// The runtime image is exercised with /tmp mounted noexec, where
	// access(X_OK) fails and no stub can be resolved. Argument and
	// environment construction is covered wherever exec is permitted.
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("temporary directory is not executable: %v", err)
	}
	t.Setenv("ENCRYPTION_KEY", "must-not-inherit")
	t.Setenv("PGHOST", "unapproved-target")
	t.Setenv("PGCHANNELBINDING", "require")
	t.Setenv("SSL_CERT_FILE", "/unapproved-host-ca.pem")
	t.Setenv("SSL_CERT_DIR", "/unapproved-host-certs")
	for _, protocol := range []string{"mysql", "postgresql", "redis", "mongodb", "http"} {
		t.Run(protocol, func(t *testing.T) {
			const password = "temporary-credential;$()'\"\\\n"
			binary, args, env, err := clientCommand(launchSpec{Protocol: protocol, Account: "admin", Password: password, Directory: dir, Port: "12345", ClientIdentity: true})
			if err != nil {
				t.Fatal(err)
			}
			if binary == "" || strings.Contains(strings.Join(args, " "), "temporary-credential") {
				t.Fatal("credential present in argv")
			}
			for _, value := range env {
				if strings.Contains(value, "must-not-inherit") || strings.Contains(value, "unapproved-") {
					t.Fatal("worker environment reached client")
				}
			}
			trust := map[string]string{}
			for _, value := range env {
				name, content, _ := strings.Cut(value, "=")
				trust[name] = content
			}
			if trust["SSL_CERT_FILE"] != filepath.Join(dir, "ca.pem") || trust["SSL_CERT_DIR"] != filepath.Join(dir, trustDirectory) {
				t.Fatal("client default TLS trust is not restricted to its private proxy CA")
			}
			if protocol == "mongodb" && !strings.Contains(strings.Join(args, " "), "--nodb") {
				t.Fatal("MongoDB connects before private bootstrap")
			}
			if protocol == "postgresql" && !strings.Contains(strings.Join(env, " "), "PGSSLMODE=verify-full") {
				t.Fatal("PostgreSQL skips proxy identity")
			}
			if protocol == "postgresql" && trust["PGCHANNELBINDING"] != "disable" {
				t.Fatal("PostgreSQL would negotiate SCRAM channel binding across separate TLS connections")
			}
			if protocol != "http" && !strings.Contains(strings.Join(append(args, env...), " "), "client.pem") {
				t.Fatal("client did not receive the temporary mutual TLS identity")
			}
			if protocol == "http" {
				if _, err := os.Stat(filepath.Join(dir, "http-login")); !os.IsNotExist(err) {
					t.Fatal("HTTP login was written to disk")
				}
				if !strings.Contains(trust["GATEWAY_HTTP_LOGIN"], "temporary-credential") {
					t.Fatal("HTTP login was not passed to the isolated client")
				}
			}
		})
	}
	if err := os.Remove(filepath.Join(bin, "mariadb")); err != nil {
		t.Fatal(err)
	}
	_, args, _, err := clientCommand(launchSpec{Protocol: "mysql", Account: "admin", Directory: dir, Port: "1"})
	if err != nil || !strings.Contains(strings.Join(args, " "), "--ssl-mode=VERIFY_IDENTITY") {
		t.Fatal("MySQL CLI fallback uses MariaDB-only flags")
	}
}
