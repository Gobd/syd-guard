//go:build linux

package main

import (
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNetworkWatchLeaseClientRejectsUnboundAcknowledgements(t *testing.T) {
	for _, kind := range []string{"role", "nonce", "uid", "index", "namespace", "sequence", "token", "no-fd", "wrong-fd", "extra-fds", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			x := newLeaseStreamFixture(t)
			fd, o, _ := x.recordNamespace(t)
			defer unix.Close(fd)
			transfer, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				req, received, err := recvNetworkWatchLeaseFrame(ctx, x.server.socket, x.server.peer, 1)
				if err != nil {
					done <- err
					return
				}
				defer unix.Close(received)
				ack := req
				ack.op = networkWatchLeaseACK
				ack.role = networkWatchWatchdog
				ack.retentionToken[0] = 7
				replyFD := received
				switch kind {
				case "role":
					ack.role = networkWatchParent
				case "nonce":
					ack.nonce[0] ^= 1
				case "uid":
					ack.uid++
				case "index":
					ack.index++
				case "namespace":
					ack.ino++
				case "sequence":
					ack.sequence++
				case "token":
					ack.retentionToken = [32]byte{}
				case "no-fd":
					replyFD = -1
				}
				if kind == "wrong-fd" {
					f, e := os.Open("/dev/null")
					if e != nil {
						done <- e
						return
					}
					defer f.Close()
					replyFD = int(f.Fd())
				}
				if kind == "truncated" {
					b := ack.bytes()
					_, err = unix.SendmsgN(x.server.socket, b[:8], unix.UnixRights(received), nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
					done <- err
					return
				}
				if kind == "extra-fds" {
					b := ack.bytes()
					_, err = unix.SendmsgN(x.server.socket, b[:], unix.UnixRights(received, received), nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
					done <- err
					return
				}
				done <- sendNetworkWatchLeaseFrame(ctx, x.server.socket, x.server.peer, ack, replyFD)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
			defer cancel()
			r, err := x.client.callbacks().lease(ctx, leaseBinding(x.f.j), o, os.NewFile(uintptr(transfer), "transfer"))
			if err == nil {
				if r.FD != nil {
					r.FD.Close()
				}
				t.Fatal("bad ACK accepted")
			}
			if e := <-done; e != nil {
				t.Fatalf("rogue sender: %v", e)
			}
			if !x.client.failed || x.client.sequence != 0 {
				t.Fatal("ambiguous ACK was not quarantined")
			}
			if _, err = x.client.callbacks().recover(context.Background(), leaseBinding(x.f.j), o); err == nil {
				t.Fatal("lost ACK allowed recovery/rebind")
			}
			if err = x.client.Close(); err == nil {
				t.Fatal("ambiguous ACK reported a clean client close")
			}
		})
	}
}
func TestNetworkWatchLeaseReleaseRequiresVerifiedCleanup(t *testing.T) {
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
	j := x.f.j
	j.Network.State = "deleting"
	if err = writeJournal(x.f.base, x.f.slot, j, false); err != nil {
		t.Fatal(err)
	}
	frame.op = networkWatchRelease
	frame.sequence = 2
	frame.retentionToken = ack.retentionToken
	done = x.serve(t, 1)
	if err = sendNetworkWatchLeaseFrame(ctx, x.client.socket, x.client.peer, frame, -1); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err == nil {
		t.Fatal("release without verified kill accepted")
	}
	if x.server.retained == nil || !x.server.poisoned {
		t.Fatal("failed release discarded retained namespace")
	}
	if _, err = x.server.retainedFDForRecovery(); err == nil {
		t.Fatal("recovery allowed before kill")
	}
}
func TestNetworkWatchLeaseRootBootstrapRejectsNonRootAndBadSocket(t *testing.T) {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		t.Skip("ordinary unprivileged bootstrap rejection")
	}
	x := newLeaseStreamFixture(t)
	if _, err := newRootNetworkWatchLeaseServer(x.server.socket, x.server.peer, x.f.base, x.f.slot, x.f.j, func() error { return nil }); err == nil {
		t.Fatal("unprivileged server accepted")
	}
	if _, err := newRootNetworkWatchLeaseClient(x.client.socket, x.f.base, x.f.slot, x.f.j, &networkChild{}); err == nil {
		t.Fatal("unprivileged client accepted")
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	if err = checkNetworkLeaseStream(pair[0]); err == nil {
		t.Fatal("non-stream lease socket accepted")
	}
}
