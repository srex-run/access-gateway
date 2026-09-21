//go:build darwin || linux

package terminalclient

import (
	"os"

	"golang.org/x/sys/unix"
)

func clientSocketDescriptor(file *os.File, flags int) (uintptr, error) {
	// File.Fd resets pollable files to blocking mode on every call. Keep this
	// descriptor after restoring the client's flags; another Fd call would
	// make libpq's idle notification read block before the next psql prompt.
	descriptor := file.Fd()
	_, err := unix.FcntlInt(descriptor, unix.F_SETFL, flags&unix.O_NONBLOCK)
	return descriptor, err
}
