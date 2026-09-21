package terminalclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The client never performs a connect syscall. Seccomp redirects every connect
// to the supervisor, which injects a socket to the approved audit proxy. Even
// shell escapes, driver discovery, URLs and reconnect commands stay inside the
// same grant. No sockaddr pointer is read or continued (avoids TOCTOU races).
func prepareCommand(ctx context.Context, cmd *exec.Cmd, _ *launchSpec, bridge Bridge, cancel context.CancelFunc) (func(), error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parent, child := os.NewFile(uintptr(fds[0]), "terminal-supervisor"), os.NewFile(uintptr(fds[1]), "terminal-supervisor-child")
	connection, err := net.FileConn(parent)
	parent.Close()
	if err != nil {
		child.Close()
		return nil, err
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, child) // fd 4; fd 3 carries the login.
	ctx, stopBroker := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		stop := context.AfterFunc(ctx, func() { connection.Close() })
		defer stop()
		_ = connection.SetReadDeadline(time.Now().Add(15 * time.Second))
		oob := make([]byte, unix.CmsgSpace(4))
		_, n, _, _, err := connection.(*net.UnixConn).ReadMsgUnix(make([]byte, 1), oob)
		if err != nil {
			return
		}
		messages, err := unix.ParseSocketControlMessage(oob[:n])
		if err != nil {
			return
		}
		var rights []int
		for _, message := range messages {
			fds, err := unix.ParseUnixRights(&message)
			if err != nil {
				continue
			}
			rights = append(rights, fds...)
		}
		defer func() {
			for _, fd := range rights {
				unix.Close(fd)
			}
		}()
		if len(rights) != 1 {
			return
		}
		unix.CloseOnExec(rights[0])
		broker(ctx, rights[0], bridge, cancel)
	}()
	return func() { stopBroker(); child.Close(); connection.Close(); <-done }, nil
}

func isolate(spec launchSpec) error {
	// Landlock/seccomp are per-thread. Exec on this locked thread atomically
	// removes all other Go runtime threads before any untrusted client runs.
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err := restrictFiles(spec.Directory); err != nil {
		return err
	}
	for resource, limit := range map[int]uint64{unix.RLIMIT_CORE: 0, unix.RLIMIT_FSIZE: 16 << 20, unix.RLIMIT_NOFILE: 256} {
		if err := unix.Setrlimit(resource, &unix.Rlimit{Cur: limit, Max: limit}); err != nil {
			return err
		}
	}
	filter := networkFilter()
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	fd, _, e := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, uintptr(unsafe.Pointer(&program)))
	if e != 0 {
		return e
	}
	if err := unix.Sendmsg(4, []byte{1}, unix.UnixRights(int(fd)), nil, 0); err != nil {
		unix.Close(int(fd))
		return err
	}
	unix.Close(4)
	unix.Close(int(fd))
	// The bootstrap socket is gone; no sendmsg with an embedded destination may
	// bypass connect interception. Connected-stream sendto(NULL) remains valid.
	final := []unix.SockFilter{load(0), jump(unix.SYS_SENDMSG, 0, 1), ret(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)), ret(unix.SECCOMP_RET_ALLOW)}
	program = unix.SockFprog{Len: uint16(len(final)), Filter: &final[0]}
	_, _, e = unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&program)))
	if e != 0 {
		return e
	}
	return nil
}

func restrictFiles(directory string) error {
	abi, _, e := unix.RawSyscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if e != 0 || abi < 1 {
		return ErrUnavailable
	}
	read := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR)
	write := uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		write |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		write |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	attr := unix.LandlockRulesetAttr{Access_fs: read | write | unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK}
	fd, _, e := unix.RawSyscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), 8, 0)
	if e != 0 {
		return e
	}
	defer unix.Close(int(fd))
	allow := func(path string, access uint64, optional bool) error {
		pathFD, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if optional && errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err != nil {
			return err
		}
		defer unix.Close(pathFD)
		var stat unix.Stat_t
		if err = unix.Fstat(pathFD, &stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			access &^= unix.LANDLOCK_ACCESS_FS_READ_DIR
		}
		rule := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(pathFD)}
		_, _, e := unix.RawSyscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
		if e != 0 {
			return e
		}
		return nil
	}
	for _, path := range []string{"/usr", "/bin", "/lib", "/lib64"} {
		if err := allow(path, read|unix.LANDLOCK_ACCESS_FS_EXECUTE, true); err != nil {
			return err
		}
	}
	for _, path := range []string{"/etc/ssl", "/etc/ld.so.cache", "/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/hosts", "/etc/localtime", "/etc/locale.alias", "/proc/meminfo", "/proc/cpuinfo", "/proc/stat", "/dev/urandom", "/dev/random"} {
		if err := allow(path, read, true); err != nil {
			return err
		}
	}
	for _, path := range []string{"/dev/null", "/dev/tty"} {
		if err := allow(path, unix.LANDLOCK_ACCESS_FS_READ_FILE|unix.LANDLOCK_ACCESS_FS_WRITE_FILE, false); err != nil {
			return err
		}
	}
	if err := allow(directory, read|write, false); err != nil {
		return err
	}
	_, _, e = unix.RawSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0)
	if e != 0 {
		return e
	}
	return nil
}

func load(offset uint32) unix.SockFilter {
	return unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offset}
}
func jump(value uint32, yes, no uint8) unix.SockFilter {
	return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: value, Jt: yes, Jf: no}
}
func ret(value uint32) unix.SockFilter {
	return unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: value}
}

func networkFilter() []unix.SockFilter {
	arch := uint32(unix.AUDIT_ARCH_X86_64)
	if runtime.GOARCH == "arm64" {
		arch = unix.AUDIT_ARCH_AARCH64
	}
	deny := uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	filter := []unix.SockFilter{load(4), jump(arch, 1, 0), ret(unix.SECCOMP_RET_KILL_PROCESS), load(0)}
	// Deny alternate networking APIs and access to sibling processes. x32
	// syscall numbers cannot match an allowed native syscall on amd64.
	for _, nr := range []uint32{unix.SYS_BIND, unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4, unix.SYS_SENDMMSG, unix.SYS_IO_URING_SETUP, unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PIDFD_GETFD, unix.SYS_PIDFD_SEND_SIGNAL, unix.SYS_KILL, unix.SYS_TKILL, unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_TGSIGQUEUEINFO, unix.SYS_SETSID, unix.SYS_SETPGID, unix.SYS_SETNS, unix.SYS_UNSHARE, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_KEYCTL, unix.SYS_SHMGET, unix.SYS_SHMAT, unix.SYS_SHMCTL, unix.SYS_MSGGET, unix.SYS_MSGSND, unix.SYS_MSGRCV, unix.SYS_MSGCTL, unix.SYS_SEMGET, unix.SYS_SEMCTL} {
		filter = append(filter, jump(nr, 0, 1), ret(deny))
	}
	filter = append(filter,
		jump(unix.SYS_CONNECT, 0, 1), ret(unix.SECCOMP_RET_USER_NOTIF),
		jump(unix.SYS_TGKILL, 0, 4), load(16), jump(uint32(os.Getpid()), 0, 1), ret(unix.SECCOMP_RET_ALLOW), ret(deny),
		// sendto is permitted only without a destination (ordinary send()).
		jump(unix.SYS_SENDTO, 0, 6), load(48), jump(0, 0, 3), load(52), jump(0, 0, 1), ret(unix.SECCOMP_RET_ALLOW), ret(deny),
		jump(unix.SYS_SOCKET, 0, 9), load(16), jump(unix.AF_INET, 1, 0), jump(unix.AF_INET6, 0, 5), load(24),
		unix.SockFilter{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: 0xf}, jump(unix.SOCK_STREAM, 0, 2), ret(unix.SECCOMP_RET_ALLOW), ret(deny), ret(deny),
	)
	if runtime.GOARCH == "amd64" {
		filter = append(filter, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: 0x40000000, Jf: 1}, ret(deny))
	}
	return append(filter, ret(unix.SECCOMP_RET_ALLOW))
}

type seccompData struct {
	Number int32
	Arch   uint32
	IP     uint64
	Args   [6]uint64
}
type notification struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  seccompData
}
type notificationResponse struct {
	ID    uint64
	Value int64
	Error int32
	Flags uint32
}
type notificationFD struct {
	ID          uint64
	Flags       uint32
	Source      uint32
	Target      uint32
	TargetFlags uint32
}

func ioctl(fd int, request uintptr, pointer unsafe.Pointer) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), request, uintptr(pointer))
	if e != 0 {
		return e
	}
	return nil
}

func broker(ctx context.Context, fd int, bridge Bridge, cancel context.CancelFunc) {
	var workers sync.WaitGroup
	defer workers.Wait()
	capacity := make(chan struct{}, 5)
	for ctx.Err() == nil {
		// Polling bounds cancellation without closing/reusing a descriptor while
		// another thread is inside ioctl. A listener is serviced by one goroutine.
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(poll, 200); errors.Is(err, unix.EINTR) {
			continue
		} else if err != nil {
			return
		}
		if poll[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			continue
		}
		var request notification
		if err := ioctl(fd, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&request)); err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.ENOENT) {
				continue
			}
			return
		}
		response := notificationResponse{ID: request.ID, Error: -int32(unix.EPERM)}
		select {
		case capacity <- struct{}{}:
		default:
			_ = ioctl(fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&response))
			continue
		}
		client, server, err := localPair(ctx)
		if err == nil {
			var file *os.File
			file, err = client.(*net.TCPConn).File()
			if err == nil {
				// Preserve nonblocking mode used by libuv/libpq/hiredis before
				// replacing the fd. No address, credentials or user memory is read.
				var flags int
				var descriptor uintptr
				flags, err = descriptorFlags(request.PID, request.Data.Args[0])
				if err == nil {
					descriptor, err = clientSocketDescriptor(file, flags)
				}
				if err == nil {
					add := notificationFD{ID: request.ID, Flags: 1, Source: uint32(descriptor), Target: uint32(request.Data.Args[0]), TargetFlags: uint32(flags & unix.O_CLOEXEC)}
					// _IOW('!', 3, struct seccomp_notif_addfd), Linux >= 5.9.
					err = ioctl(fd, 0x40182103, unsafe.Pointer(&add))
				}
				file.Close()
			}
			client.Close()
		}
		if err != nil {
			if server != nil {
				server.Close()
			}
			<-capacity
			_ = ioctl(fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&response))
			continue
		}
		response.Error = 0
		if err := ioctl(fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&response)); err != nil {
			server.Close()
			<-capacity
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { server.Close(); <-capacity }()
			stop := context.AfterFunc(ctx, func() { server.Close() })
			defer stop()
			if bridge(ctx, server) != nil && ctx.Err() == nil {
				cancel()
			}
		}()
	}
}

func descriptorFlags(pid uint32, fd uint64) (int, error) {
	if fd > 1<<20 {
		return 0, ErrUnavailable
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "flags:\t"); ok {
			flags, err := strconv.ParseInt(value, 8, 32)
			return int(flags), err
		}
	}
	return 0, ErrUnavailable
}

func localPair(ctx context.Context) (net.Conn, net.Conn, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()
	client, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	for {
		server, err := listener.Accept()
		if err != nil {
			client.Close()
			return nil, nil, err
		}
		if server.RemoteAddr().String() == client.LocalAddr().String() {
			return client, server, nil
		}
		server.Close()
	}
}
