//go:build linux

package main

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNetworkChildPinsExecutableAndPidfd(t *testing.T) {
	binary, err := os.Open("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	defer binary.Close()
	cmd := exec.Command("/bin/sleep", "30")
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
	}()
	child, err := pinNetworkChild(cmd.Process.Pid, pidfd, binary)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	if err := child.verify(); err != nil {
		t.Fatal(err)
	}
	other, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if wrong, err := pinNetworkChild(cmd.Process.Pid, pidfd, other); err == nil {
		_ = wrong.Close()
		t.Fatal("accepted wrong executable")
	}
	if wrong, err := pinNetworkChild(cmd.Process.Pid+1, pidfd, binary); err == nil {
		_ = wrong.Close()
		t.Fatal("accepted wrong pid")
	}
	if wrong, err := pinNetworkChild(cmd.Process.Pid, int(binary.Fd()), binary); err == nil {
		_ = wrong.Close()
		t.Fatal("accepted non-pidfd")
	}
	if err := unix.Close(pidfd); err != nil {
		t.Fatal(err)
	}
	pidfd = -1
	if err := child.verify(); err != nil {
		t.Fatalf("duplicated pidfd lost after original close: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for child.verify() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := child.verify(); err == nil {
		t.Fatal("dead child accepted")
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.verify(); err == nil {
		t.Fatal("closed child accepted")
	}
}
