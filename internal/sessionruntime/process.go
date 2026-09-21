package sessionruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type processDriver struct {
	binary string
	store  *hostStore
	mu     sync.Mutex
	active map[string]*os.Process
}

func (d *processDriver) Ready(context.Context) error {
	info, err := os.Stat(d.binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("session agent binary must be an executable file without group/world write permission")
	}
	return nil
}

// The lock is inherited by the child before exec. This closes the gap where a
// restarted controller could mistake a not-yet-scheduled child for an exit.
func (d *processDriver) Start(ctx context.Context, record hostRecord) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	lock, busy, err := processLock(d.store.agentPath(record.SessionID))
	if err != nil {
		return "", err
	}
	if busy {
		return "", fmt.Errorf("session process is already running")
	}
	defer lock.Close()
	log, err := os.OpenFile(filepath.Join(d.store.agentPath(record.SessionID), "agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", err
	}
	defer log.Close()
	cmd := exec.Command(d.binary, "session", "--config", d.store.grantPath(record.SessionID), "--state-dir", d.store.agentPath(record.SessionID), "--lock-fd", "3")
	cmd.ExtraFiles = []*os.File{lock}
	cmd.Dir = d.store.agentPath(record.SessionID)
	// Native web clients are resolved on the development host. Pass only PATH,
	// never the control plane's database credentials or authentication settings.
	cmd.Env = []string{"LANG=C", "TZ=UTC", "PATH=" + os.Getenv("PATH")}
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start session agent process: %w", err)
	}
	d.mu.Lock()
	d.active[record.SessionID] = cmd.Process
	d.mu.Unlock()
	go func() {
		_ = cmd.Wait()
		d.mu.Lock()
		delete(d.active, record.SessionID)
		d.mu.Unlock()
	}()
	return record.SessionID, nil
}

func (d *processDriver) Inspect(_ context.Context, record hostRecord) (hostResource, error) {
	lock, busy, err := processLock(d.store.agentPath(record.SessionID))
	if os.IsNotExist(err) {
		return hostResource{}, nil
	}
	if err != nil {
		return hostResource{}, err
	}
	if lock != nil {
		_ = lock.Close()
	}
	return hostResource{ID: record.SessionID, Exists: busy, Running: busy}, nil
}

func (d *processDriver) Stop(ctx context.Context, record hostRecord) error {
	// Only signal a process handle retained from exec.Start, never a stored PID.
	// After a controller restart the durable stop marker is consumed by the agent.
	d.mu.Lock()
	if process := d.active[record.SessionID]; process != nil {
		if err := process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			d.mu.Unlock()
			return err
		}
	}
	d.mu.Unlock()
	return pollHost(ctx, 100*time.Millisecond, func() (bool, error) {
		resource, err := d.Inspect(ctx, record)
		return !resource.Running, err
	})
}

func (d *processDriver) Remove(context.Context, hostRecord) error { return nil }

func processLock(directory string) (*os.File, bool, error) {
	file, err := os.OpenFile(filepath.Join(directory, "agent.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, false, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = file.Close()
		return nil, false, fmt.Errorf("session process lock is not private")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return file, false, nil
}
