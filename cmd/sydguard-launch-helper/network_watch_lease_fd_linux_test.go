//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNetworkWatchLeaseTruncatedRightsDoNotLeak(t *testing.T) {
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 16; n++ {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			x := newLeaseStreamFixture(t)
			fd, _, frame := x.recordNamespace(t)
			defer unix.Close(fd)
			rights := make([]int, 32)
			for i := range rights {
				rights[i] = fd
			}
			done := x.serve(t, 1)
			b := frame.bytes()
			sent, err := unix.SendmsgN(x.client.socket, b[:], unix.UnixRights(rights...), nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
			if err != nil || sent != len(b) {
				t.Fatalf("send %d: %v", sent, err)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("truncated rights accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("truncated rights blocked")
			}
		})
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatalf("rights leak: %d -> %d: %v", len(before), len(after), err)
	}
}
func TestNetworkWatchLeaseRejectsUnexpectedCredentials(t *testing.T) {
	x := newLeaseStreamFixture(t)
	fd, _, frame := x.recordNamespace(t)
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(x.server.socket, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		t.Fatal(err)
	}
	done := x.serve(t, 1)
	b := frame.bytes()
	cred := &unix.Ucred{Pid: int32(os.Getpid()), Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid())}
	oob := append(unix.UnixCredentials(cred), unix.UnixRights(fd)...)
	n, err := unix.SendmsgN(x.client.socket, b[:], oob, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
	if err != nil || n != len(b) {
		t.Fatalf("send %d: %v", n, err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unexpected credentials accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("credentials blocked")
	}
}
func TestNetworkWatchLeaseCancellationBeforeRequestNoLease(t *testing.T) {
	x := newLeaseStreamFixture(t)
	fd, o, _ := x.recordNamespace(t)
	defer unix.Close(fd)
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = x.client.callbacks().lease(ctx, leaseBinding(x.f.j), o, os.NewFile(uintptr(dup), "namespace-transfer")); err == nil {
		t.Fatal("canceled request accepted")
	}
	// No request was attempted, so the client has not manufactured a lease.
	if x.client.sequence != 0 || x.server.retained != nil {
		t.Fatal("canceled request created lease")
	}
}
