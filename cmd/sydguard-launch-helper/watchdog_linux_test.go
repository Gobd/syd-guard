//go:build linux

package main

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestWaitWatchdogEventSocketAndPidfd(t *testing.T) {
	for _, eventKind := range []string{"control", "eof", "pidfd"} {
		t.Run(eventKind, func(t *testing.T) {
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.Close(pair[0]) }()
			peer := pair[1]
			defer func() {
				if peer >= 0 {
					_ = unix.Close(peer)
				}
			}()
			cmd := exec.Command("/bin/sleep", "30")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.Close(pidfd) }()
			switch eventKind {
			case "control":
				if _, err := unix.Write(peer, []byte{'X'}); err != nil {
					t.Fatal(err)
				}
			case "eof":
				if err := unix.Close(peer); err != nil {
					t.Fatal(err)
				}
				peer = -1
			case "pidfd":
				if err := cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
			}
			event, err := waitWatchdogEvent(pidfd, pair[0])
			if err != nil || event.at.IsZero() || event.count != 1 {
				t.Fatalf("event=%+v err=%v", event, err)
			}
			if eventKind == "pidfd" {
				if event.pidfdRevents&unix.POLLIN == 0 || event.socketRevents != 0 {
					t.Fatalf("event=%+v", event)
				}
			} else if event.socketRevents&unix.POLLIN == 0 || event.pidfdRevents != 0 {
				t.Fatalf("event=%+v", event)
			}
			if eventKind == "eof" && event.socketRevents&unix.POLLHUP == 0 {
				t.Fatalf("missing HUP: %+v", event)
			}
			if eventKind == "control" {
				var buf [1]byte
				if n, err := unix.Read(pair[0], buf[:]); err != nil || n != 1 || buf[0] != 'X' {
					t.Fatalf("poll consumed control: %d %q %v", n, buf, err)
				}
			}
		})
	}
}

func TestWatchdogHasIndependentUnmountedRecoveryNamespace(t *testing.T) {
	attributes := watchdogProcessAttributes()
	if !attributes.Setsid || attributes.Cloneflags != unix.CLONE_NEWNS {
		t.Fatalf("watchdog must clone mount namespace independently: %+v", attributes)
	}
}

func TestWatchdogSocketpairSupportsBoundedHandshake(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := os.NewFile(uintptr(pair[0]), "a"), os.NewFile(uintptr(pair[1]), "b")
	defer func() { _ = a.Close(); _ = b.Close() }()
	if err := a.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := b.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write([]byte("R")); err != nil {
		t.Fatal(err)
	}
	var value [1]byte
	if _, err := b.Read(value[:]); err != nil || value[0] != 'R' {
		t.Fatalf("socket handshake: %q %v", value, err)
	}
}

func TestWatchdogPidfdDetectsParentDeath(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		t.Fatalf("required pidfd unavailable: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	//nolint:gosec // Linux file descriptors are nonnegative signed 32-bit values
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 0); err != nil || n != 0 {
		t.Fatalf("live process marked exited: %d %v", n, err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if n, err := unix.Poll(poll, 5000); err != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
		t.Fatalf("pidfd did not detect death: %d %v", n, err)
	}
}
