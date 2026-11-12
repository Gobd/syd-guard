//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func lifecycleFixture(t *testing.T) (string, string, int, int, *launchSlot, uint32) {
	t.Helper()
	base, group := t.TempDir(), t.TempDir()
	baseFD, err := unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	groupFD, err := unix.Open(group, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(baseFD); _ = unix.Close(groupFD) })
	owner := uint32(os.Getuid()) //nolint:gosec // Linux getuid returns a kernel uid_t
	slot, err := acquireLaunchSlot(baseFD, owner, owner, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slot.Close() })
	return base, group, baseFD, groupFD, slot, owner
}

func emptyCgroup(int, time.Duration) error { return nil }

func TestSlotJournalQuarantinesPartialAndUnrecordedResources(t *testing.T) {
	base, group, baseFD, groupFD, slot, owner := lifecycleFixture(t)
	j, err := newJournal(slot, "test-identity")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJournal(baseFD, slot, j, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, anchorName(slot)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := recoverSlot(baseFD, groupFD, slot, owner, emptyCgroup); err == nil {
		t.Fatal("preparing resource was reused")
	}
	if _, err := os.Stat(filepath.Join(base, anchorName(slot))); err != nil {
		t.Fatal("unverified anchor was removed")
	}
	if _, err := os.Stat(filepath.Join(group, slotName(slot.UID, slot.Index))); !os.IsNotExist(err) {
		t.Fatal("unexpected cgroup")
	}
}

func TestSlotRecoveryRetainsUntrustedScratchAndReusesOnlyAfterCleanup(t *testing.T) {
	base, group, baseFD, groupFD, slot, owner := lifecycleFixture(t)
	j, cg, err := prepareSlot(baseFD, groupFD, slot, "test-identity", owner, emptyCgroup)
	if err != nil {
		t.Fatal(err)
	}
	if err := cg.Close(); err != nil {
		t.Fatal(err)
	}
	anchor := filepath.Join(base, anchorName(slot))
	for _, child := range []string{"project", "policy", "work"} {
		if err := os.Mkdir(filepath.Join(anchor, child), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(anchor, "work", "untrusted")
	if err := os.WriteFile(file, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupSlot(baseFD, groupFD, slot, j, owner, emptyCgroup); err == nil {
		t.Fatal("nonempty scratch unexpectedly cleaned")
	}
	//nolint:gosec // test-owned path
	if data, err := os.ReadFile(file); err != nil || string(data) != "keep" {
		t.Fatalf("untrusted tree removed: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(group, slotName(slot.UID, slot.Index))); err != nil {
		t.Fatal("cgroup removed before scratch cleanup")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := recoverSlot(baseFD, groupFD, slot, owner, emptyCgroup); err != nil {
		t.Fatal(err)
	}
	if err := recoverSlot(baseFD, groupFD, slot, owner, emptyCgroup); err != nil {
		t.Fatalf("clean slot unavailable: %v", err)
	}
}

func TestSlotRecoveryRejectsChangedIdentityAndPopulatedCgroup(t *testing.T) {
	base, _, baseFD, groupFD, slot, owner := lifecycleFixture(t)
	j, cg, err := prepareSlot(baseFD, groupFD, slot, "test-identity", owner, emptyCgroup)
	if err != nil {
		t.Fatal(err)
	}
	if err := cg.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cleanupSlot(baseFD, groupFD, slot, j, owner, func(int, time.Duration) error { return errors.New("populated") }); err == nil {
		t.Fatal("populated cgroup reused")
	}
	anchor := filepath.Join(base, anchorName(slot))
	if err := os.Rename(anchor, anchor+"-moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(anchor, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := recoverSlot(baseFD, groupFD, slot, owner, emptyCgroup); err == nil {
		t.Fatal("replaced anchor accepted")
	}
	if _, err := os.Stat(anchor); err != nil {
		t.Fatal("replacement anchor removed")
	}
}

func TestQuarantinedSlotsCountAgainstBound(t *testing.T) {
	base, _, baseFD, groupFD, first, owner := lifecycleFixture(t)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < launchSlotsPerUID; index++ {
		name := slotName(owner, index) + ".journal.pending"
		if err := os.WriteFile(filepath.Join(base, name), []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	selected, err := acquireLaunchSlot(baseFD, owner, owner, func(slot *launchSlot) error {
		return recoverSlot(baseFD, groupFD, slot, owner, emptyCgroup)
	})
	if err == nil {
		_ = selected.Close()
		t.Fatal("reused quarantined slot")
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2*launchSlotsPerUID {
		t.Fatalf("unexpected unbounded state: %d", len(entries))
	}
}

func TestSlotRecoveryNeverKillsReplacedCgroup(t *testing.T) {
	_, group, baseFD, groupFD, slot, owner := lifecycleFixture(t)
	_, cg, err := prepareSlot(baseFD, groupFD, slot, "test-identity", owner, emptyCgroup)
	if err != nil {
		t.Fatal(err)
	}
	if err := cg.Close(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(group, slotName(slot.UID, slot.Index))
	if err := os.Rename(name, name+"-moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(name, 0o700); err != nil {
		t.Fatal(err)
	}
	called := false
	kill := func(int, time.Duration) error { called = true; return nil }
	if err := recoverSlot(baseFD, groupFD, slot, owner, kill); err == nil {
		t.Fatal("replaced cgroup accepted")
	}
	if called {
		t.Fatal("unverified cgroup was killed")
	}
}

func TestKillCgroupWaitsForEmptyAndRejectsMalformedEvents(t *testing.T) {
	path := t.TempDir()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	killPath, events := filepath.Join(path, "cgroup.kill"), filepath.Join(path, "cgroup.events")
	if err := os.WriteFile(killPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(events, []byte("populated 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := killCgroup(fd, 20*time.Millisecond); err == nil {
		t.Fatal("populated group accepted")
	}
	if err := os.WriteFile(events, []byte("populated 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := killCgroup(fd, 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(events, []byte("populated 0\npopulated 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := killCgroup(fd, 20*time.Millisecond); err == nil {
		t.Fatal("duplicate populated state accepted")
	}
}

func TestSlotJournalRejectsPartialTemporaryFile(t *testing.T) {
	base, _, baseFD, groupFD, slot, owner := lifecycleFixture(t)
	if err := os.WriteFile(filepath.Join(base, journalTempName(slot)), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverSlot(baseFD, groupFD, slot, owner, emptyCgroup); err == nil {
		t.Fatal("partial journal accepted")
	}
}
