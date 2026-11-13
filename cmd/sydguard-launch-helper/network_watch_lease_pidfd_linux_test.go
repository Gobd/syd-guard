//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNetworkWatchLeaseRealPidfdPeerExit(t *testing.T) {
	if os.Getenv("SYDGUARD_LEASE_PIDFD_FIXTURE") == "1" {
		time.Sleep(150 * time.Millisecond)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNetworkWatchLeaseRealPidfdPeerExit$")
	cmd.Env = append(os.Environ(), "SYDGUARD_LEASE_PIDFD_FIXTURE=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		_ = cmd.Wait()
		t.Fatal(err)
	}
	defer unix.Close(pidfd)
	if err = verifyPidfdPID(pidfd, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatal(err)
	}
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		_ = cmd.Wait()
		t.Fatal(err)
	}
	defer unix.Close(sockets[0])
	defer unix.Close(sockets[1])
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err = pollNetworkLease(ctx, sockets[0], pidfd, unix.POLLIN); err == nil {
		t.Fatal("peer exit not detected")
	}
	if err = cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}
