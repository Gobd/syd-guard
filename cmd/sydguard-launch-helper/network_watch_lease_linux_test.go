//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type leaseStreamFixture struct {
	f       *adapterNativeFixture
	server  *networkWatchLeaseServer
	client  *networkWatchLeaseClient
	allowed atomic.Bool
}

func newLeaseStreamFixture(t *testing.T) *leaseStreamFixture {
	t.Helper()
	f := newAdapterNativeFixture(t)
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal(err)
	}
	dup := func(fd int) int {
		v, e := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	slot := func() *launchSlot {
		return &launchSlot{File: os.NewFile(uintptr(dup(int(f.slot.File.Fd()))), "test-slot"), UID: f.slot.UID, Index: f.slot.Index}
	}
	x := &leaseStreamFixture{f: f}
	x.server = &networkWatchLeaseServer{socket: sockets[1], peer: dup(peer), base: dup(f.base), slot: slot(), initial: f.j, owner: f.owner, releaseAuthorized: func() error {
		if !x.allowed.Load() {
			return errors.New("cgroup kill not verified")
		}
		return nil
	}}
	x.client = &networkWatchLeaseClient{socket: sockets[0], peer: peer, base: dup(f.base), slot: slot(), initial: f.j, owner: f.owner, verifyPeer: func() error { return pollNetworkLeasePeer(peer) }}
	t.Cleanup(func() {
		if x.server.retained != nil {
			_ = x.server.retained.Close()
			x.server.retained = nil
		}
		_ = x.server.Close()
		_ = x.client.Close()
	})
	return x
}
func (x *leaseStreamFixture) serve(t *testing.T, limit int) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		for i := 0; i < limit; i++ {
			if err := x.server.handleNetworkLease(context.Background()); err != nil {
				done <- err
				return
			}
			if x.server.released {
				done <- nil
				return
			}
		}
		done <- nil
	}()
	return done
}
func TestNetworkWatchLeaseRealStreamAdapterRetentionRecoveryRelease(t *testing.T) {
	x := newLeaseStreamFixture(t)
	x.f.a.callbacks = x.client.callbacks()
	done := make(chan error, 1)
	go func() { done <- x.server.serveNetworkLease(context.Background()) }()
	if err := x.f.prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	o := x.f.j.Network.Objects[0]
	if err := x.f.a.namespace.Close(); err != nil {
		t.Fatal(err)
	}
	x.f.a.namespace = nil
	if err := x.f.a.lease.Close(); err != nil {
		t.Fatal(err)
	}
	x.f.a.lease = nil
	if err := x.f.a.ensureLease(context.Background(), o, true); err != nil {
		t.Fatal(err)
	}
	if err := verifyNetworkNamespaceFD(int(x.f.a.lease.Fd()), o); err != nil {
		t.Fatal(err)
	}
	if err := cleanupSlotWithNetwork(x.f.base, x.f.group, x.f.slot, x.f.j, x.f.owner, func(int, time.Duration) error { x.allowed.Store(true); return nil }, x.f.a); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("watchdog did not acknowledge release")
	}
	if x.server.retained != nil || !x.server.released || !x.client.released {
		t.Fatal("release was not acknowledged after retention dropped")
	}
}
func TestNetworkWatchLeaseParentDeathPreservesRetainedFDForCleanup(t *testing.T) {
	x := newLeaseStreamFixture(t)
	x.f.a.callbacks = x.client.callbacks()
	done := x.serve(t, 1)
	if err := x.f.prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// The next request handler observes parent death before socket readability.
	pipe := []int{0, 0}
	if err := unix.Pipe2(pipe, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pipe[1])
	unix.Close(x.server.peer)
	x.server.peer = pipe[0]
	if _, err := unix.Write(pipe[1], []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := x.server.handleNetworkLease(context.Background()); err == nil {
		t.Fatal("parent death ignored")
	}
	if err := x.server.Close(); err == nil {
		t.Fatal("retained namespace was silently released")
	}
	if _, err := x.server.retainedFDForRecovery(); err == nil {
		t.Fatal("recovery before cgroup kill")
	}
	x.allowed.Store(true)
	result, err := x.server.retainedFDForRecovery()
	if err != nil {
		t.Fatal(err)
	}
	defer result.FD.Close()
	if err := verifyLeaseResult(result, leaseBinding(x.f.j), x.f.j.Network.Objects[0]); err != nil {
		t.Fatal(err)
	}
}
func TestNetworkWatchLeaseStreamFDZeroTransfer(t *testing.T) {
	if os.Getenv("SYDGUARD_LEASE_FD_ZERO_FIXTURE") == "1" {
		x := newLeaseStreamFixture(t)
		fd, object, frame := x.recordNamespace(t)
		if err := unix.Dup3(fd, 0, unix.O_CLOEXEC); err != nil {
			unix.Close(fd)
			t.Fatal(err)
		}
		unix.Close(fd)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := sendNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, frame, 0); err != nil {
			t.Fatal(err)
		}
		if err := unix.Close(0); err != nil {
			t.Fatal(err)
		}
		done := x.serve(t, 1)
		ack, returned, err := recvNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, 1)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(returned)
		if err = verifyNetworkNamespaceFD(returned, object); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err != nil {
			t.Fatal(err)
		}
		if ack.op != networkWatchLeaseACK || x.server.retained == nil || x.server.retained.Fd() != 0 {
			t.Fatal("FD zero was not retained as the received namespace")
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNetworkWatchLeaseStreamFDZeroTransfer$")
	cmd.Env = append(os.Environ(), "SYDGUARD_LEASE_FD_ZERO_FIXTURE=1")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("FD zero fixture: %v %s", err, b)
	}
}
