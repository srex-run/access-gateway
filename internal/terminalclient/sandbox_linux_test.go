package terminalclient

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Runs as a real isolated subprocess; test code never restricts the test runner.
func sandboxProbe() int {
	input := os.NewFile(3, "probe-config")
	var spec launchSpec
	if json.NewDecoder(input).Decode(&spec) != nil {
		return 1
	}
	input.Close()
	if err := isolate(spec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	private := filepath.Join(filepath.Dir(spec.Directory), "private-canary")
	script := `if cat "$1"; then exit 2; fi
if cat /proc/$PPID/environ; then exit 3; fi
exec 5<>/dev/tcp/203.0.113.123/9 || exit 4
printf 'approved\n' >&5
IFS= read -r response <&5
[ "$response" = approved ] || exit 5
printf 'isolated-ok\n'
`
	if err := syscall.Exec("/bin/bash", []string{"bash", "--noprofile", "--norc", "-c", script, "probe", private}, []string{"PATH=/usr/bin:/bin"}); err != nil {
		return 1
	}
	return 0
}

func TestLinuxClientNetworkAndFileIsolation(t *testing.T) {
	if os.Getenv("RUN_TERMINAL_SANDBOX_TESTS") != "1" {
		t.Skip("set RUN_TERMINAL_SANDBOX_TESTS=1 on Linux with Landlock to exercise the real sandbox")
	}
	dir := t.TempDir()
	private := filepath.Join(dir, "private-canary")
	if err := os.WriteFile(private, []byte("must-not-leak"), 0600); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(dir, "client")
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	cmd := exec.CommandContext(ctx, os.Args[0], "sandbox-probe")
	cmd.ExtraFiles = []*os.File{input}
	spec := launchSpec{Directory: work}
	var connections atomic.Int32
	cleanup, err := prepareCommand(ctx, cmd, &spec, func(_ context.Context, conn net.Conn) error {
		connections.Add(1)
		_, err := io.Copy(conn, conn)
		return err
	}, cancel)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	go func() { _ = json.NewEncoder(writer).Encode(spec); writer.Close() }()
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "isolated-ok") || strings.Contains(string(output), "must-not-leak") || connections.Load() != 1 {
		t.Fatalf("sandbox probe: %v, output=%q, approved connections=%d", err, output, connections.Load())
	}
}

// A small BPF interpreter checks branches for every sensitive syscall, so
// offsets cannot accidentally turn a deny rule into a network bypass.
func filterResult(number uint32, arch uint32, args ...uint64) uint32 {
	var data [64]byte
	binary.LittleEndian.PutUint32(data[:], number)
	binary.LittleEndian.PutUint32(data[4:], arch)
	for i, arg := range args {
		binary.LittleEndian.PutUint64(data[16+8*i:], arg)
	}
	var a uint32
	code := networkFilter()
	for pc := 0; pc < len(code); pc++ {
		i := code[pc]
		switch i.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			a = binary.LittleEndian.Uint32(data[i.K:])
		case unix.BPF_ALU | unix.BPF_AND | unix.BPF_K:
			a &= i.K
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if a == i.K {
				pc += int(i.Jt)
			} else {
				pc += int(i.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			if a&i.K != 0 {
				pc += int(i.Jt)
			} else {
				pc += int(i.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return i.K
		default:
			panic("unsupported BPF instruction")
		}
	}
	panic("filter fell through")
}

func TestLinuxClientSeccompRoutesConnectionsAndRejectsBypasses(t *testing.T) {
	arch := uint32(unix.AUDIT_ARCH_X86_64)
	if runtime.GOARCH == "arm64" {
		arch = unix.AUDIT_ARCH_AARCH64
	}
	check := func(nr uint32, action uint32, args ...uint64) {
		t.Helper()
		if got := filterResult(nr, arch, args...); got&unix.SECCOMP_RET_ACTION_FULL != action {
			t.Fatalf("syscall %d args %v: %#x", nr, args, got)
		}
	}
	check(unix.SYS_READ, unix.SECCOMP_RET_ALLOW)
	check(unix.SYS_CONNECT, unix.SECCOMP_RET_USER_NOTIF)
	check(unix.SYS_SOCKET, unix.SECCOMP_RET_ALLOW, unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	check(unix.SYS_SOCKET, unix.SECCOMP_RET_ALLOW, unix.AF_INET6, unix.SOCK_STREAM, 0)
	check(unix.SYS_SOCKET, unix.SECCOMP_RET_ERRNO, unix.AF_UNIX, unix.SOCK_STREAM, 0)
	check(unix.SYS_SOCKET, unix.SECCOMP_RET_ERRNO, unix.AF_INET, unix.SOCK_DGRAM, 0)
	check(unix.SYS_SOCKET, unix.SECCOMP_RET_ERRNO, unix.AF_PACKET, unix.SOCK_RAW, 0)
	check(unix.SYS_SENDTO, unix.SECCOMP_RET_ALLOW, 5, 1, 1, 0, 0)
	check(unix.SYS_SENDTO, unix.SECCOMP_RET_ERRNO, 5, 1, 1, 0, 1)
	check(unix.SYS_SENDTO, unix.SECCOMP_RET_ERRNO, 5, 1, 1, 0, 1<<32)
	check(unix.SYS_TGKILL, unix.SECCOMP_RET_ALLOW, uint64(os.Getpid()), uint64(os.Getpid()), 0)
	check(unix.SYS_TGKILL, unix.SECCOMP_RET_ERRNO, 1, 1, 0)
	for _, nr := range []uint32{unix.SYS_IO_URING_SETUP, unix.SYS_SENDMMSG, unix.SYS_BIND, unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PIDFD_GETFD, unix.SYS_SETNS, unix.SYS_UNSHARE, unix.SYS_SETSID, unix.SYS_SETPGID, unix.SYS_KILL, unix.SYS_RT_SIGQUEUEINFO} {
		check(nr, unix.SECCOMP_RET_ERRNO)
	}
	if runtime.GOARCH == "amd64" {
		check(unix.SYS_CONNECT|0x40000000, unix.SECCOMP_RET_ERRNO)
	}
	if filterResult(unix.SYS_CONNECT, unix.AUDIT_ARCH_I386) != unix.SECCOMP_RET_KILL_PROCESS {
		t.Fatal("alternate syscall ABI accepted")
	}
}
