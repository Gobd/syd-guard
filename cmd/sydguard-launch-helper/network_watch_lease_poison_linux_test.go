//go:build linux

package main

import (
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNetworkWatchLeaseInitialACKSendFailureKeepsDurableQuarantine(t *testing.T) {
	x := newLeaseStreamFixture(t)
	fd, o, frame := x.recordNamespace(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Queue a valid FD-bearing request, then disallow reading the ACK before the
	// handler starts; the retained FD is real and ACK transmission fails.
	if err := sendNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, frame, fd); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	unix.Close(fd)
	if err := unix.Shutdown(x.client.socket, unix.SHUT_RD); err != nil {
		t.Fatal(err)
	}
	if err := x.server.handleNetworkLease(ctx); err == nil {
		t.Fatal("ACK send unexpectedly succeeded")
	}
	if !x.server.poisoned || x.server.retained == nil {
		t.Fatal("ACK send failure lost retained namespace or poison")
	}
	assertNetworkLeaseDurableQuarantine(t, x, o)
}
func TestNetworkWatchLeaseEstablishedPoisonKeepsDurableQuarantine(t *testing.T) {
	for _, kind := range []string{"replay", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			x := newLeaseStreamFixture(t)
			x.f.a.callbacks = x.client.callbacks()
			done := x.serve(t, 1)
			if err := x.f.prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			o := x.f.j.Network.Objects[0]
			nonce, err := networkLeaseNonce(x.f.j.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			frame := networkWatchLeaseFrame{op: networkWatchLease, role: networkWatchParent, uid: x.f.j.UID, index: uint32(x.f.j.Index), nonce: nonce, dev: o.Dev, ino: o.Ino, sequence: 1}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done = x.serve(t, 1)
			if kind == "replay" {
				if err = sendNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, frame, int(x.f.a.namespace.Fd())); err != nil {
					t.Fatal(err)
				}
			} else {
				b := frame.bytes()
				b[0] = 'X'
				n, e := unix.SendmsgN(x.client.socket, b[:], nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
				if e != nil || n != len(b) {
					t.Fatalf("send malformed %d %v", n, e)
				}
			}
			if err = <-done; err == nil {
				t.Fatal("poisoning request accepted")
			}
			if !x.server.poisoned {
				t.Fatal("server not poisoned")
			}
			assertNetworkLeaseDurableQuarantine(t, x, o)
		})
	}
}

// A transport intermediary here is only a test instrument: it corrupts a real
// ACK after the server has sent it, leaving server.poisoned false while the
// actual client has a sticky negative/unknown acknowledgement disposition.
func TestNetworkWatchLeaseClientPoisonWithoutServerPoisonStillQuarantines(t *testing.T) {
	x := newLeaseStreamFixture(t)
	fd, o, _ := x.recordNamespace(t)
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	clientPair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	serverPair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		unix.Close(clientPair[0])
		unix.Close(clientPair[1])
		t.Fatal(err)
	}
	unix.Close(x.client.socket)
	unix.Close(x.server.socket)
	x.client.socket = clientPair[0]
	x.server.socket = serverPair[0]
	defer unix.Close(clientPair[1])
	defer unix.Close(serverPair[1])
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverDone := x.serve(t, 1)
	proxyDone := make(chan error, 1)
	go func() {
		req, requestFD, e := recvNetworkWatchLeaseFrame(ctx, clientPair[1], x.client.peer, 1)
		if e != nil {
			proxyDone <- e
			return
		}
		defer unix.Close(requestFD)
		if e = sendNetworkWatchLeaseFrame(ctx, serverPair[1], x.server.peer, req, requestFD); e != nil {
			proxyDone <- e
			return
		}
		ack, ackFD, e := recvNetworkWatchLeaseFrame(ctx, serverPair[1], x.server.peer, 1)
		if e != nil {
			proxyDone <- e
			return
		}
		defer unix.Close(ackFD)
		ack.nonce[0] ^= 1
		proxyDone <- sendNetworkWatchLeaseFrame(ctx, clientPair[1], x.client.peer, ack, ackFD)
	}()
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		t.Fatal(err)
	}
	result, err := x.client.callbacks().lease(ctx, leaseBinding(x.f.j), o, os.NewFile(uintptr(dup), "lease-transfer"))
	if err == nil {
		if result.FD != nil {
			result.FD.Close()
		}
		t.Fatal("corrupted ACK accepted")
	}
	if err = <-proxyDone; err != nil {
		t.Fatal(err)
	}
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
	if !x.client.failed || x.server.poisoned || x.server.retained == nil {
		t.Fatal("expected client-only uncertain disposition")
	}
	if _, err = x.client.callbacks().recover(ctx, leaseBinding(x.f.j), o); err == nil {
		t.Fatal("client retried ambiguous lease")
	}
	if err = unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	fd = -1
	assertNetworkLeaseDurableQuarantine(t, x, o)
}
func TestNetworkWatchLeasePrivateReleaseRefusesBeforeKill(t *testing.T) {
	x := newLeaseStreamFixture(t)
	fd, o, frame := x.recordNamespace(t)
	defer unix.Close(fd)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := x.serve(t, 1)
	if err := sendNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, frame, fd); err != nil {
		t.Fatal(err)
	}
	_, ackFD, err := recvNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, 1)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(ackFD)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	j := x.f.j
	j.Network.State = "deleting"
	if err = writeJournal(x.f.base, x.f.slot, j, false); err != nil {
		t.Fatal(err)
	}
	retained := x.server.retained
	if err = x.server.cleanupCallbacks().release(ctx, leaseBinding(j), o); err == nil {
		t.Fatal("release allowed before kill")
	}
	if _, err = retained.Stat(); err != nil || x.server.retained != retained {
		t.Fatalf("retained FD lost before kill: %v", err)
	}
	persisted, exists, err := readJournal(x.f.base, x.f.slot, x.f.owner)
	if err != nil || !exists || persisted.Network.State != "deleting" {
		t.Fatalf("deleting journal lost: %v", err)
	}
}
