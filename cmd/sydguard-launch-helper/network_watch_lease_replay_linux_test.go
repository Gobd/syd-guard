//go:build linux

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNetworkWatchLeaseRejectsStalePersistedGeneration(t *testing.T) {
	x := newLeaseStreamFixture(t)
	fd, _, frame := x.recordNamespace(t)
	defer unix.Close(fd)
	changed := x.f.j
	changed.Nonce = strings.Repeat("a", 64)
	if changed.Nonce == x.f.j.Nonce {
		changed.Nonce = strings.Repeat("b", 64)
	}
	if err := writeJournal(x.f.base, x.f.slot, changed, false); err != nil {
		t.Fatal(err)
	}
	done := x.serve(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sendNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, frame, fd); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("stale lifecycle generation accepted")
	}
	if x.server.retained != nil {
		t.Fatal("stale generation retained namespace")
	}
}
func TestNetworkWatchLeaseRejectsNonCloexecRetainedFD(t *testing.T) {
	x := newLeaseStreamFixture(t)
	fd, _, frame := x.recordNamespace(t)
	defer unix.Close(fd)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := x.serve(t, 1)
	if err := sendNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, frame, fd); err != nil {
		t.Fatal(err)
	}
	ack, received, err := recvNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, 1)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(received)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if _, err = unix.FcntlInt(x.server.retained.Fd(), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	x.allowed.Store(true)
	if _, err = x.server.retainedFDForRecovery(); err == nil {
		t.Fatal("non-CLOEXEC retained FD accepted")
	}
	frame.op = networkWatchRecover
	frame.sequence = 2
	frame.retentionToken = ack.retentionToken
	done = x.serve(t, 1)
	if err = sendNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, frame, -1); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err == nil {
		t.Fatal("non-CLOEXEC recovery acknowledged")
	}
}

func TestNetworkWatchLeaseRejectsSecondRecovery(t *testing.T) {
	x := newLeaseStreamFixture(t)
	fd, _, frame := x.recordNamespace(t)
	defer unix.Close(fd)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := x.serve(t, 1)
	if err := sendNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, frame, fd); err != nil {
		t.Fatal(err)
	}
	ack, received, err := recvNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, 1)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(received)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	frame.op = networkWatchRecover
	frame.sequence = 2
	frame.retentionToken = ack.retentionToken
	done = x.serve(t, 1)
	if err = sendNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, frame, -1); err != nil {
		t.Fatal(err)
	}
	ack, received, err = recvNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, 1)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(received)
	if ack.op != networkWatchRecoverACK {
		t.Fatal("missing recovery ack")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	frame.sequence = 3
	done = x.serve(t, 1)
	if err = sendNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, frame, -1); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err == nil {
		t.Fatal("duplicate recovery accepted")
	}
	if x.server.retained == nil || !x.server.poisoned {
		t.Fatal("duplicate recovery lost retained FD")
	}
}
