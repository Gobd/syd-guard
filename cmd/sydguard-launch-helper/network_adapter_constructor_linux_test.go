//go:build linux

package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNewManagedNetworkAdapterRejectsInvalidBorrowedInputsWithoutLeaks(t *testing.T) {
	_, base, _, slot, owner, j, _ := networkFixture(t)
	listeners, err := prebindNetworkListeners(context.Background(), base, slot, owner, j)
	if err != nil {
		t.Fatal(err)
	}
	defer listeners.Close()
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)
	unsafeDir := t.TempDir()
	if err := os.Chmod(unsafeDir, 0o770); err != nil {
		t.Fatal(err)
	}
	unsafeFD, err := unix.Open(unsafeDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(unsafeFD)
	var unsafeStat unix.Stat_t
	if err := unix.Fstat(unsafeFD, &unsafeStat); err != nil || unsafeStat.Mode&0o020 == 0 {
		t.Fatalf("test directory is not group-writable: mode %#o, error %v", unsafeStat.Mode, err)
	}
	ns, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ns)
	var rootStat, nsStat unix.Stat_t
	if err = unix.Fstat(root, &rootStat); err != nil {
		t.Fatal(err)
	}
	if err = unix.Fstat(ns, &nsStat); err != nil {
		t.Fatal(err)
	}
	rootJournal := j
	rootJournal.AnchorDev = rootStat.Dev
	rootJournal.AnchorIno = rootStat.Ino
	host := networkObject{Kind: "namespace", Dev: nsStat.Dev, Ino: nsStat.Ino}
	callbacks := namespaceLeaseCallbacks{lease: func(context.Context, namespaceLeaseBinding, networkObject, *os.File) (namespaceLeaseResult, error) {
		t.Fatal("unexpected lease")
		return namespaceLeaseResult{}, nil
	}, recover: func(context.Context, namespaceLeaseBinding, networkObject) (namespaceLeaseResult, error) {
		t.Fatal("unexpected recovery")
		return namespaceLeaseResult{}, nil
	}, release: func(context.Context, namespaceLeaseBinding, networkObject) error {
		t.Fatal("unexpected release")
		return nil
	}}
	cases := []struct {
		name             string
		base, anchor, ns int
		host             networkObject
		owner            uint32
		expected         string
	}{
		{"nonroot-owner", root, root, ns, host, 1, "invalid root network adapter binding"},
		{"bad-base", -1, root, ns, host, 0, ""},
		{"bad-anchor", root, -1, ns, host, 0, ""},
		{"bad-host", root, root, -1, host, 0, ""},
		{"host-inode", root, root, ns, networkObject{Kind: "namespace", Dev: host.Dev, Ino: host.Ino + 1}, 0, "network namespace identity changed"},
		{"unsafe-root-directory", unsafeFD, root, ns, host, 0, "unsafe root network directories"},
		{"stale-journal-after-all-duplicates", root, root, ns, host, 0, "stale network adapter journal"},
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for i := 0; i < 10; i++ {
				a, err := newManagedNetworkAdapter(c.base, c.anchor, c.ns, c.host, slot, c.owner, rootJournal, listeners, callbacks)
				if err == nil {
					a.Close()
					t.Fatal("invalid constructor accepted")
				}
				if c.expected != "" && !strings.Contains(err.Error(), c.expected) {
					t.Fatalf("got %v want %q", err, c.expected)
				}
			}
		})
	}
	for _, missing := range []string{"lease", "recover", "release", "listeners", "slot", "journal"} {
		t.Run("missing-"+missing, func(t *testing.T) {
			c, l, s, candidate := callbacks, listeners, slot, rootJournal
			switch missing {
			case "lease":
				c.lease = nil
			case "recover":
				c.recover = nil
			case "release":
				c.release = nil
			case "listeners":
				l = nil
			case "slot":
				s = nil
			case "journal":
				candidate.Nonce = "invalid"
			}
			a, err := newManagedNetworkAdapter(root, root, ns, host, s, 0, candidate, l, c)
			if err == nil {
				a.Close()
				t.Fatal("missing authority accepted")
			}
		})
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatalf("constructor leaked FDs: %d -> %d: %v", len(before), len(after), err)
	}
	for _, fd := range []int{root, ns, base, unsafeFD} {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			t.Fatalf("borrowed FD closed: %v", err)
		}
	}
	if _, _, err = firewallPorts(generatedNetworkPlan(j), listeners, listeners.namespaceCookie); err != nil {
		t.Fatalf("borrowed listeners closed: %v", err)
	}
}
