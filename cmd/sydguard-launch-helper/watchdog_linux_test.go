//go:build linux

package main

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

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
