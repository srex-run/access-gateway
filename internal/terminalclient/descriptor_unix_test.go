//go:build darwin || linux

package terminalclient

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestClientSocketDescriptorPreservesReadMode(t *testing.T) {
	for _, nonblocking := range []bool{false, true} {
		t.Run(fmt.Sprintf("nonblocking=%v", nonblocking), func(t *testing.T) {
			// os.Pipe gives us a pollable *os.File without opening a listener.
			// Like TCPConn.File(), File.Fd() resets it to blocking mode.
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			flags := 0
			if nonblocking {
				flags = unix.O_NONBLOCK
			}
			descriptor, err := clientSocketDescriptor(reader, flags)
			if err != nil {
				t.Fatal(err)
			}
			got, err := unix.FcntlInt(descriptor, unix.F_GETFL, 0)
			if err != nil || (got&unix.O_NONBLOCK != 0) != nonblocking {
				t.Fatalf("descriptor read mode changed: flags=%#x, want nonblocking=%v, err=%v", got, nonblocking, err)
			}
			if nonblocking {
				if _, err := unix.Read(int(descriptor), make([]byte, 1)); !errors.Is(err, unix.EAGAIN) {
					t.Fatalf("idle client socket must return EAGAIN instead of waiting: %v", err)
				}
			}
			if _, err := writer.Write([]byte{'x'}); err != nil {
				t.Fatal(err)
			}
			var data [1]byte
			if n, err := unix.Read(int(descriptor), data[:]); err != nil || n != 1 || data[0] != 'x' {
				t.Fatalf("descriptor response changed: n=%d data=%q err=%v", n, data, err)
			}
		})
	}
}
