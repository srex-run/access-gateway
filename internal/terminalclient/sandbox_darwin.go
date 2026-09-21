package terminalclient

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// macOS development uses the operating system sandbox. Only the one local
// proxy endpoint is reachable. Deployment uses the Linux syscall supervisor.
func prepareCommand(ctx context.Context, command *exec.Cmd, spec *launchSpec, bridge Bridge, cancel context.CancelFunc) (func(), error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	spec.Port = strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	var terminalPath string
	if tty, ok := command.Stdin.(*os.File); ok {
		terminalPath = tty.Name()
	}
	profile := darwinProfile(command.Path, spec.Directory, spec.Port, terminalPath)
	path := filepath.Join(spec.Directory, "client.sb")
	if err = os.WriteFile(path, []byte(profile), 0600); err != nil {
		listener.Close()
		return nil, err
	}
	command.Args = append([]string{"/usr/bin/sandbox-exec", "-f", path, command.Path}, command.Args[1:]...)
	command.Path = "/usr/bin/sandbox-exec"
	ctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var workers sync.WaitGroup
		defer workers.Wait()
		capacity := make(chan struct{}, 5)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case capacity <- struct{}{}:
			default:
				conn.Close()
				continue
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { conn.Close(); <-capacity }()
				closeOnCancel := context.AfterFunc(ctx, func() { conn.Close() })
				defer closeOnCancel()
				if bridge(ctx, conn) != nil && ctx.Err() == nil {
					cancel()
				}
			}()
		}
	}()
	return func() { stop(); listener.Close(); <-done }, nil
}

func darwinProfile(executable, directory, port, terminalPath string) string {
	quote := func(value string) string { return strconv.Quote(value) }
	// Resolve /var -> /private/var and Homebrew symlinks before applying rules.
	if value, err := filepath.EvalSymlinks(directory); err == nil {
		directory = value
	}
	if value, err := filepath.EvalSymlinks(executable); err == nil {
		executable = value
	}
	var profile strings.Builder
	// Use Apple's loader bootstrap rules. Recent macOS libignition opens "/"
	// as its openat root before Go starts; denying that aborts the helper in
	// dyld before it can print an error. This import grants loader access only,
	// without recursively allowing user files or granting network access.
	profile.WriteString("(version 1)\n(deny default)\n(import \"dyld-support.sb\")\n(allow process-fork)\n(allow signal (target self))\n(allow sysctl-read)\n")
	for _, path := range []string{"/System", "/usr/bin", "/usr/lib", "/usr/share", "/bin", "/Library/Apple", "/opt/homebrew/Cellar", "/opt/homebrew/opt", "/opt/homebrew/lib", "/usr/local/Cellar", "/usr/local/opt", "/usr/local/lib"} {
		fmt.Fprintf(&profile, "(allow file-read* process-exec (subpath %s))\n", quote(path))
	}
	fmt.Fprintf(&profile, "(allow file-read* process-exec (literal %s))\n", quote(executable))
	for _, path := range []string{"/private/etc/hosts", "/private/etc/passwd", "/private/etc/group", "/private/etc/localtime", "/dev/random", "/dev/urandom", "/dev/null", "/dev/tty"} {
		fmt.Fprintf(&profile, "(allow file-read* (literal %s))\n", quote(path))
	}
	fmt.Fprintf(&profile, "(allow file-read* file-write* (subpath %s) (literal \"/dev/null\") (literal \"/dev/tty\"))\n", quote(directory))
	if strings.HasPrefix(terminalPath, "/dev/ttys") && filepath.Dir(terminalPath) == "/dev" {
		// libedit/readline need tcgetattr/tcsetattr, window size and foreground
		// process-group ioctls. File read/write permission alone omits these.
		fmt.Fprintf(&profile, "(allow file-read* file-write* file-ioctl (literal %s))\n", quote(terminalPath))
	}
	// Seatbelt accepts only "localhost" or "*" as the host in a network
	// filter. Keep both the loopback restriction and the exact TCP proxy port.
	fmt.Fprintf(&profile, "(allow network-outbound (remote tcp %s))\n", quote("localhost:"+port))
	return profile.String()
}

func isolate(_ launchSpec) error {
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}
