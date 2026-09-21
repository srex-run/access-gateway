package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestInitialPasswordIsPrivateAndReusable(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "initial-admin-password")
	first, err := initialPassword(path)
	if err != nil || len(first) != 43 {
		t.Fatalf("generate password: length=%d error=%v", len(first), err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("password file must be owner-read-only: %v", err)
	}
	second, err := initialPassword(path)
	if err != nil || second != first {
		t.Fatalf("retry replaced the initial password: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary credentials left behind: count=%d error=%v", len(entries), err)
	}
}

func TestInitialPasswordPreservesProvidedSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "initial-admin-password")
	const provided = "provided-initial-password"
	if err := os.WriteFile(path, []byte(provided+"\r\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	password, err := initialPassword(path)
	if err != nil || password != provided {
		t.Fatalf("provided password was not reused: %v", err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil || string(encoded) != provided+"\r\n" {
		t.Fatalf("provided password file was modified: %v", err)
	}
}

func TestInitialPasswordConcurrentPublication(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "initial-admin-password")
	values := make([]string, 8)
	errors := make([]error, len(values))
	var group sync.WaitGroup
	for index := range values {
		group.Go(func() { values[index], errors[index] = initialPassword(path) })
	}
	group.Wait()
	for index, value := range values {
		if errors[index] != nil || value == "" || value != values[0] {
			t.Fatalf("concurrent publisher %d did not reuse the committed file: %v", index, errors[index])
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary credentials left behind: count=%d error=%v", len(entries), err)
	}
}

func TestInitialPasswordRejectsUnsafePaths(t *testing.T) {
	directory := t.TempDir()
	safe := filepath.Join(directory, "safe")
	if err := os.WriteFile(safe, []byte("already-configured-password\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(safe, link); err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(directory, "public")
	if err := os.WriteFile(public, []byte("not-a-private-password-file"), 0o644); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(directory, "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", "relative-password", link, public, filepath.Join(shared, "password")} {
		if _, err := initialPassword(path); err == nil {
			t.Errorf("unsafe password path was accepted: %q", path)
		}
	}
	encoded, err := os.ReadFile(safe)
	if err != nil || !strings.HasPrefix(string(encoded), "already-configured-") {
		t.Fatal("symlink target changed")
	}
}
