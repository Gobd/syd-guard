//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func (x *leaseStreamFixture) recordNamespace(t *testing.T) (int, networkObject, networkWatchLeaseFrame) {
	t.Helper()
	fd, o, err := x.f.a.ops.createNamespace(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	j := x.f.j
	j.Network = &networkJournal{State: "recorded", Objects: []networkObject{o}}
	if err = writeJournal(x.f.base, x.f.slot, j, false); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	x.f.j = j
	nonce, err := networkLeaseNonce(j.Nonce)
	if err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	return fd, o, networkWatchLeaseFrame{op: networkWatchLease, role: networkWatchParent, uid: j.UID, index: uint32(j.Index), nonce: nonce, dev: o.Dev, ino: o.Ino, sequence: 1}
}
func TestNetworkWatchLeaseRejectsBadFramesAndAncillary(t *testing.T) {
	for _, kind := range []string{"role", "nonce", "uid", "index", "namespace-identity", "sequence", "token", "unknown-op", "no-fd", "wrong-fd", "two-fds", "truncated-control", "bad-header"} {
		t.Run(kind, func(t *testing.T) {
			x := newLeaseStreamFixture(t)
			fd, _, frame := x.recordNamespace(t)
			defer unix.Close(fd)
			switch kind {
			case "role":
				frame.role = networkWatchWatchdog
			case "nonce":
				frame.nonce[0] ^= 1
			case "uid":
				frame.uid++
			case "index":
				frame.index++
			case "namespace-identity":
				frame.ino++
			case "sequence":
				frame.sequence = 2
			case "token":
				frame.retentionToken[0] = 1
			case "unknown-op":
				frame.op = 99
			}
			transfer := fd
			var bad *os.File
			if kind == "no-fd" {
				transfer = -1
			}
			if kind == "wrong-fd" {
				var err error
				bad, err = os.Open("/dev/null")
				if err != nil {
					t.Fatal(err)
				}
				defer bad.Close()
				transfer = int(bad.Fd())
			}
			done := x.serve(t, 1)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if kind == "two-fds" || kind == "truncated-control" || kind == "bad-header" {
				b := frame.bytes()
				if kind == "bad-header" {
					b[0] = 'Z'
				}
				var rights []int
				switch kind {
				case "two-fds":
					rights = []int{fd, fd}
				case "truncated-control":
					for i := 0; i < 32; i++ {
						rights = append(rights, fd)
					}
				case "bad-header":
					rights = []int{fd}
				}
				n, err := unix.SendmsgN(x.client.socket, b[:], unix.UnixRights(rights...), nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
				if err != nil || n != len(b) {
					t.Fatalf("send %d: %v", n, err)
				}
			} else if err := sendNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, frame, transfer); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("invalid request accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("invalid request blocked")
			}
			if x.server.retained != nil || !x.server.poisoned {
				t.Fatal("invalid request acquired lease or left channel retryable")
			}
		})
	}
}
func TestNetworkWatchLeaseRejectsTruncatedFrameAndCancellation(t *testing.T) {
	x := newLeaseStreamFixture(t)
	fd, _, frame := x.recordNamespace(t)
	defer unix.Close(fd)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- x.server.handleNetworkLease(ctx) }()
	b := frame.bytes()
	n, err := unix.SendmsgN(x.client.socket, b[:7], unix.UnixRights(fd), nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
	if err != nil || n != 7 {
		t.Fatalf("send: %d %v", n, err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("truncated frame failed to time out")
	}
	if x.server.retained != nil || !x.server.poisoned {
		t.Fatal("partial frame acquired lease")
	}
}
func TestNetworkWatchLeaseRejectsDuplicateAndStaleRequests(t *testing.T) {
	x := newLeaseStreamFixture(t)
	fd, _, frame := x.recordNamespace(t)
	defer unix.Close(fd)
	done := x.serve(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
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
	if ack.op != networkWatchLeaseACK || ack.role != networkWatchWatchdog || ack.retentionToken == ([32]byte{}) {
		t.Fatal("invalid retention acknowledgement")
	}
	done = x.serve(t, 1)
	if err = sendNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, frame, fd); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err == nil {
		t.Fatal("duplicate lease accepted")
	}
	if !x.server.poisoned || x.server.retained == nil {
		t.Fatal("replay did not quarantine retained lease")
	}
	x.allowed.Store(true)
	r, err := x.server.retainedFDForRecovery()
	if err != nil {
		t.Fatal(err)
	}
	r.FD.Close()
}
func TestNetworkWatchLeaseSentAckParentDeathBeforeRead(t *testing.T) {
	x := newLeaseStreamFixture(t)
	fd, o, frame := x.recordNamespace(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := x.serve(t, 1)
	if err := sendNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, frame, fd); err != nil {
		t.Fatal(err)
	}
	unix.Close(fd)
	if err := <-done; err != nil {
		t.Fatal(err)
	} // ACK was sent, not necessarily received.
	unix.Close(x.client.socket)
	x.client.socket = -1
	pipe := []int{0, 0}
	if err := unix.Pipe2(pipe, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pipe[1])
	unix.Close(x.server.peer)
	x.server.peer = pipe[0]
	unix.Write(pipe[1], []byte{1})
	if err := x.server.handleNetworkLease(ctx); err == nil {
		t.Fatal("parent loss not detected")
	}
	assertNetworkLeaseDurableQuarantine(t, x, o)
}
