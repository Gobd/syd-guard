//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLaunchSlotsBoundIsolationAndRelease(t *testing.T) {
	base := t.TempDir()
	fd, err := unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	owner := uint32(os.Getuid()) //nolint:gosec // Linux getuid returns a kernel uid_t
	var slots []*launchSlot
	defer func() {
		for _, slot := range slots {
			_ = slot.Close()
		}
	}()
	for range launchSlotsPerUID {
		slot, err := acquireLaunchSlot(fd, 1000, owner, nil)
		if err != nil {
			t.Fatalf("acquire slot: %v", err)
		}
		slots = append(slots, slot)
	}
	if slot, err := acquireLaunchSlot(fd, 1000, owner, nil); err == nil {
		_ = slot.Close()
		t.Fatal("exceeded per-UID capacity")
	}
	other, err := acquireLaunchSlot(fd, 1001, owner, nil)
	if err != nil {
		t.Fatalf("different UID blocked: %v", err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	if err := slots[0].Close(); err != nil {
		t.Fatal(err)
	}
	slots = slots[1:]
	// Closing during a failed or canceled startup releases the flock without
	// unlinking its persistent root-owned slot inode.
	reused, err := acquireLaunchSlot(fd, 1000, owner, nil)
	if err != nil {
		t.Fatalf("released slot not reusable: %v", err)
	}
	if err := reused.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "uid-1000-slot-0")); err != nil {
		t.Fatalf("slot unexpectedly removed: %v", err)
	}
}

func TestLaunchSlotsRejectSymlinkAndUnsafeInode(t *testing.T) {
	for _, kind := range []string{"symlink", "mode", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			fd, err := unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.Close(fd) }()
			path := filepath.Join(base, "uid-1000-slot-0")
			switch kind {
			case "symlink":
				if err := os.Symlink("/dev/null", path); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				//nolint:gosec // deliberately unsafe test inode
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(path, filepath.Join(base, "alias")); err != nil {
					t.Fatal(err)
				}
			}
			owner := uint32(os.Getuid()) //nolint:gosec // Linux getuid returns a kernel uid_t
			if slot, err := acquireLaunchSlot(fd, 1000, owner, nil); err == nil {
				_ = slot.Close()
				t.Fatal("accepted unsafe slot inode")
			}
		})
	}
}
