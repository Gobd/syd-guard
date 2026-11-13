//go:build linux

package nl

import (
	"errors"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func TestGetNetlinkSocketFailureOwnership(t *testing.T) {
	sentinel := errors.New("injected socket setup failure")
	for _, stage := range []string{"nonblock", "bind"} {
		t.Run(stage, func(t *testing.T) {
			fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			socket := func(int, int, int) (int, error) { return fd, nil }
			nonblock := func(int, bool) error {
				if stage == "nonblock" {
					return sentinel
				}
				return nil
			}
			bind := func(int, unix.Sockaddr) error { return sentinel }
			_, err = getNetlinkSocketWith(0, socket, nonblock, bind)
			if !errors.Is(err, sentinel) {
				t.Fatalf("got %v", err)
			}
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Fatalf("descriptor leaked: %v", err)
			}
			// Reuse the exact descriptor; a stale os.File finalizer must not close it.
			replacement, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			if replacement != fd {
				if err := unix.Dup3(replacement, fd, unix.O_CLOEXEC); err != nil {
					unix.Close(replacement)
					t.Fatal(err)
				}
				unix.Close(replacement)
			}
			defer unix.Close(fd)
			for i := 0; i < 5; i++ {
				runtime.GC()
				runtime.Gosched()
			}
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
				t.Fatalf("replacement closed by stale owner: %v", err)
			}
		})
	}
}

func TestPrivateRequestMissingFamilyDoesNotOpenSocket(t *testing.T) {
	req := NewNetlinkRequest(0, 0)
	req.Sockets = map[int]*SocketHandle{}
	if _, err := req.Execute(unix.NETLINK_ROUTE, 0); err == nil {
		t.Fatal("missing private socket fell back")
	}
}
