//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type forbiddenLeaseCleanupAdapter struct{}

func (forbiddenLeaseCleanupAdapter) Create(context.Context, networkPlan, string) (networkObject, error) {
	panic("unexpected create")
}
func (forbiddenLeaseCleanupAdapter) Activate(context.Context, networkPlan, []networkObject) error {
	panic("unexpected activation")
}
func (forbiddenLeaseCleanupAdapter) RemoveIfIdentityMatches(context.Context, networkPlan, networkObject) error {
	panic("deleting journal was retried")
}

// This uses actual slot/journal files and the production cleanup/recovery paths.
// Only cgroup kill and network kernel operations are simulated by the fixture.
func assertNetworkLeaseDurableQuarantine(t *testing.T, x *leaseStreamFixture, o networkObject) {
	t.Helper()
	if x.server.retained == nil {
		t.Fatal("missing retained namespace")
	}
	held := x.server.retained
	if _, err := x.server.retainedFDForRecovery(); err == nil {
		t.Fatal("namespace exposed before verified kill")
	}
	x.f.a.callbacks = x.server.cleanupCallbacks()
	if x.f.a.namespace != nil {
		if err := x.f.a.namespace.Close(); err != nil {
			t.Fatal(err)
		}
		x.f.a.namespace = nil
	}
	if x.f.a.lease != nil {
		if err := x.f.a.lease.Close(); err != nil {
			t.Fatal(err)
		}
		x.f.a.lease = nil
	}
	basePath, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", x.f.base))
	if err != nil {
		t.Fatal(err)
	}
	groupPath, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", x.f.group))
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(basePath, journalName(x.f.slot))
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	killCalled := false
	err = cleanupSlotWithNetwork(x.f.base, x.f.group, x.f.slot, x.f.j, x.f.owner, func(int, time.Duration) error { killCalled = true; return errors.New("simulated kill rejected") }, x.f.a)
	if err == nil || !killCalled {
		t.Fatal("failed cgroup kill did not stop cleanup")
	}
	if _, err = held.Stat(); err != nil {
		t.Fatalf("namespace released before successful kill: %v", err)
	}
	afterFailedKill, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(before, afterFailedKill) {
		t.Fatalf("journal changed after failed kill: %v", err)
	}
	killCalled = false
	err = cleanupSlotWithNetwork(x.f.base, x.f.group, x.f.slot, x.f.j, x.f.owner, func(int, time.Duration) error { killCalled = true; x.allowed.Store(true); return nil }, x.f.a)
	if !killCalled || !errors.Is(err, errNetworkLeaseQuarantine) {
		t.Fatalf("verified cleanup did not quarantine: kill=%t err=%v", killCalled, err)
	}
	if x.server.retained != nil || !x.server.released {
		t.Fatal("verified cleanup did not close retained namespace")
	}
	if err = x.server.serveNetworkLease(context.Background()); !errors.Is(err, errNetworkLeaseQuarantine) {
		t.Fatalf("released loop lost uncertainty: %v", err)
	}
	if _, err = held.Stat(); err == nil {
		t.Fatal("retained namespace FD remained open")
	}
	j, exists, err := readJournal(x.f.base, x.f.slot, x.f.owner)
	if err != nil || !exists || j.Network == nil || j.Network.State != "deleting" || len(j.Network.Objects) != 1 || j.Network.Objects[0] != o {
		t.Fatalf("durable deleting journal missing: %+v %v", j, err)
	}
	snapshot, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("quarantined pid=%d uid=%d slot=%d nonce=%s namespace_dev=%d namespace_ino=%d journal=%s state=%s", os.Getpid(), j.UID, j.Index, j.Nonce, o.Dev, o.Ino, journalPath, j.Network.State)
	// Drop every original and duplicated slot owner, then open fresh directory and
	// slot descriptors. Retained network FDs have already been safely released.
	if err = x.server.Close(); !errors.Is(err, errNetworkLeaseQuarantine) {
		t.Fatalf("server close failed to preserve quarantine: %v", err)
	}
	_ = x.client.Close()
	x.f.a.Close()
	if err = x.f.slot.Close(); err != nil {
		t.Fatal(err)
	}
	freshBase, err := unix.Open(basePath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(freshBase)
	freshGroup, err := unix.Open(groupPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(freshGroup)
	fd, err := unix.Openat(freshBase, slotName(j.UID, j.Index), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(fd)
		t.Fatalf("old slot owner still holds flock: %v", err)
	}
	candidate := &launchSlot{File: os.NewFile(uintptr(fd), "fresh-slot"), UID: j.UID, Index: j.Index}
	persisted, exists, err := readJournal(freshBase, candidate, x.f.owner)
	if err != nil || !exists || persisted.Network == nil || persisted.Network.State != "deleting" || persisted.Nonce != j.Nonce {
		candidate.Close()
		t.Fatalf("fresh journal mismatch: %+v %v", persisted, err)
	}
	err = recoverSlot(freshBase, freshGroup, candidate, x.f.owner, func(int, time.Duration) error { return nil })
	if err == nil {
		candidate.Close()
		t.Fatal("fresh recovery reused quarantined slot")
	}
	t.Logf("fresh_recovery_error=%v", err)
	err = cleanupSlotWithNetwork(freshBase, freshGroup, candidate, persisted, x.f.owner, func(int, time.Duration) error { return nil }, forbiddenLeaseCleanupAdapter{})
	if err == nil || !strings.Contains(err.Error(), "ambiguous network resource phase") {
		candidate.Close()
		t.Fatalf("deleting phase retried: %v", err)
	}
	t.Logf("fresh_authenticated_cleanup_error=%v", err)
	if err = candidate.Close(); err != nil {
		t.Fatal(err)
	}
	var firstErr error
	replacement, err := acquireLaunchSlot(freshBase, j.UID, x.f.owner, func(s *launchSlot) error {
		if s.Index == j.Index {
			firstErr = recoverSlot(freshBase, freshGroup, s, x.f.owner, func(int, time.Duration) error { return nil })
			return firstErr
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if firstErr == nil || replacement.Index == j.Index {
		t.Fatal("quarantined slot was reacquired")
	}
	final, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(snapshot, final) {
		t.Fatalf("fresh recovery changed quarantine journal: %v", err)
	}
	t.Logf("fresh_acquisition_skipped_slot=%d replacement_slot=%d fresh_recovery_error=%v", j.Index, replacement.Index, firstErr)
}
