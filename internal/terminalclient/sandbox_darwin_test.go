package terminalclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func sandboxProbe() int {
	if _, err := os.ReadFile(os.Getenv("TERMINAL_TEST_PRIVATE")); !errors.Is(err, os.ErrPermission) {
		fmt.Fprintln(os.Stderr, "private file was not denied:", err)
		return 1
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("TERMINAL_TEST_DIRECTORY"), "client-state"), []byte("allowed"), 0600); err != nil {
		fmt.Fprintln(os.Stderr, "client cannot write its own state:", err)
		return 1
	}
	conn, err := net.DialTimeout("tcp4", os.Getenv("TERMINAL_TEST_DENIED"), time.Second)
	if err == nil {
		conn.Close()
		fmt.Fprintln(os.Stderr, "unapproved loopback port was reachable")
		return 1
	}
	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		fmt.Fprintln(os.Stderr, "unapproved port did not fail because of sandbox policy:", err)
		return 1
	}
	conn, err = net.DialTimeout("tcp4", os.Getenv("TERMINAL_TEST_PROXY"), time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "approved proxy was blocked:", err)
		return 1
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	const message = "isolated-ok"
	if _, err := io.WriteString(conn, message); err != nil {
		return 1
	}
	response := make([]byte, len(message))
	if _, err := io.ReadFull(conn, response); err != nil || string(response) != message {
		return 1
	}
	fmt.Println(message)
	return 0
}

func TestMacClientProfileOnlyAllowsItsProxy(t *testing.T) {
	profile := darwinProfile("/tmp/gateway-agent", "/tmp/terminal-private", "45678", "/dev/ttys123")
	if !strings.Contains(profile, `(remote tcp "localhost:45678")`) || strings.Count(profile, "network-") != 1 {
		t.Fatal("network scope is not restricted to the session proxy")
	}
	if !strings.Contains(profile, `(allow file-read* file-write* file-ioctl (literal "/dev/ttys123"))`) || strings.Count(profile, "file-ioctl") != 1 || strings.Contains(profile, `(subpath "/dev")`) {
		t.Fatal("terminal control is not restricted to this session's PTY")
	}
	for _, forbidden := range []string{"/run/session", "/var/run/docker.sock", "(allow default)", "(subpath \"/\")"} {
		if strings.Contains(profile, forbidden) {
			t.Fatal("sandbox exposes worker state")
		}
	}
}

func TestMacClientNetworkAndFileIsolation(t *testing.T) {
	if os.Getenv("RUN_TERMINAL_SANDBOX_TESTS") != "1" {
		t.Skip("set RUN_TERMINAL_SANDBOX_TESTS=1 to exercise sandbox-exec on macOS")
	}
	directory := t.TempDir()
	private := filepath.Join(directory, "private-canary")
	if err := os.WriteFile(private, []byte("must-not-leak"), 0600); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(directory, "client")
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	denied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "sandbox-probe")
	spec := launchSpec{Directory: work}
	var connections atomic.Int32
	cleanup, err := prepareCommand(ctx, command, &spec, func(_ context.Context, conn net.Conn) error {
		connections.Add(1)
		_, err := io.Copy(conn, conn)
		return err
	}, cancel)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	command.Env = []string{"TERMINAL_TEST_PRIVATE=" + private, "TERMINAL_TEST_DIRECTORY=" + work,
		"TERMINAL_TEST_DENIED=" + denied.Addr().String(), "TERMINAL_TEST_PROXY=127.0.0.1:" + spec.Port}
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "isolated-ok") || connections.Load() != 1 {
		t.Fatalf("sandbox probe: %v, output=%q, approved connections=%d", err, output, connections.Load())
	}
}
