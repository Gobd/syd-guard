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

func TestManagedNetworkAdapterSuccessfulRecoveryOwnsNamespaceLease(t *testing.T) {
	f := newAdapterNativeFixture(t)
	if err := f.prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	object := f.j.Network.Objects[0]
	dup, err := unix.FcntlInt(f.a.lease.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		t.Fatal(err)
	}
	recovery := os.NewFile(uintptr(dup), "recovery-lease")
	defer recovery.Close()
	if err = f.a.namespace.Close(); err != nil {
		t.Fatal(err)
	}
	f.a.namespace = nil
	if err = f.a.lease.Close(); err != nil {
		t.Fatal(err)
	}
	f.a.lease = nil
	calls := 0
	f.a.callbacks.recover = func(ctx context.Context, b namespaceLeaseBinding, o networkObject) (namespaceLeaseResult, error) {
		calls++
		if b != f.a.binding || o != object {
			return namespaceLeaseResult{}, errors.New("wrong recovery binding")
		}
		return namespaceLeaseResult{b, o, recovery}, nil
	}
	if err = f.a.ensureLease(context.Background(), object, true); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || f.a.lease != recovery {
		t.Fatal("recovery descriptor not owned")
	}
	if err = verifyNetworkNamespaceFD(int(recovery.Fd()), object); err != nil {
		t.Fatalf("duplicate invalid after originals closed: %v", err)
	}
	if err = cleanupSlotWithNetwork(f.base, f.group, f.slot, f.j, f.owner, func(int, time.Duration) error { return nil }, f.a); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("recovered %d times", calls)
	}
	if _, err = recovery.Stat(); err == nil {
		t.Fatal("released recovery lease remains open")
	}
}
