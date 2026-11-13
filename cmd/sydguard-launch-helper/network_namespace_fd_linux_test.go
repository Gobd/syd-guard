//go:build linux

package main

import (
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func namespaceHandoffFixture(t *testing.T) (*os.File, networkObject, [2]int) {
	t.Helper()
	// Inspect the test process's existing namespace; do not create or enter one.
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ns.Close() })
	var st unix.Stat_t
	if err := unix.Fstat(int(ns.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(pair[0]); _ = unix.Close(pair[1]) })
	return ns, networkObject{Kind: "namespace", Dev: st.Dev, Ino: st.Ino}, pair
}

func TestNetworkNamespacePrivateFDHandoff(t *testing.T) {
	ns, object, pair := namespaceHandoffFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sendNetworkNamespace(ctx, pair[0], ns, object); err != nil {
		t.Fatal(err)
	}
	received, err := receiveNetworkNamespace(ctx, pair[1], object)
	if err != nil {
		t.Fatal(err)
	}
	defer received.Close()
	flags, err := unix.FcntlInt(received.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("namespace FD not close-on-exec", err)
	}
	if err := verifyNetworkNamespaceFD(int(received.Fd()), object); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkNamespaceHandoffRejectsWrongIdentityAndExtraFDs(t *testing.T) {
	ns, object, pair := namespaceHandoffFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	wrong := object
	wrong.Ino++
	if err := sendNetworkNamespace(ctx, pair[0], ns, wrong); err == nil {
		t.Fatal("wrong namespace sent")
	}
	rights := unix.UnixRights(int(ns.Fd()), int(ns.Fd()))
	if _, err := unix.SendmsgN(pair[0], []byte{'N'}, rights, nil, 0); err != nil {
		t.Fatal(err)
	}
	if f, err := receiveNetworkNamespace(ctx, pair[1], object); err == nil {
		_ = f.Close()
		t.Fatal("extra descriptor accepted")
	}
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := verifyNetworkNamespaceFD(int(file.Fd()), object); err == nil {
		t.Fatal("regular FD accepted")
	}
}

func TestNetworkNamespaceHandoffDeadline(t *testing.T) {
	_, object, pair := namespaceHandoffFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if f, err := receiveNetworkNamespace(ctx, pair[1], object); err == nil {
		_ = f.Close()
		t.Fatal("empty channel accepted")
	}
}
