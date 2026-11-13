//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNetworkSetupRejectsStaleJournalBeforeWriting(t *testing.T) {
	base, baseFD, _, slot, owner, stale, f := networkFixture(t)
	active := stale
	if err := prepareNetwork(context.Background(), baseFD, slot, owner, &active, f); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, journalName(slot))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f.events = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := prepareNetwork(ctx, baseFD, slot, owner, &stale, f); err == nil {
		t.Fatal("accepted canceled stale journal")
	}
	if err := prepareNetwork(context.Background(), baseFD, slot, owner, &stale, f); err == nil {
		t.Fatal("accepted stale journal")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("durable state changed", err)
	}
	if len(f.events) != 0 {
		t.Fatalf("unexpected adapter calls: %v", f.events)
	}
}

func TestConcurrentNetworkSetupSerializesJournal(t *testing.T) {
	_, baseFD, _, slot, owner, initial, f := networkFixture(t)
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			candidate := initial
			results <- prepareNetwork(context.Background(), baseFD, slot, owner, &candidate, f)
		}()
	}
	one, two := <-results, <-results
	if (one == nil) == (two == nil) {
		t.Fatalf("expected exactly one successful transaction: %v, %v", one, two)
	}
	if len(f.events) != len(networkKinds)+1 {
		t.Fatalf("unexpected adapter operations: %v", f.events)
	}
}

func TestNetworkSetupRejectsChangedBindings(t *testing.T) {
	base, baseFD, _, slot, owner, initial, f := networkFixture(t)
	path := filepath.Join(base, journalName(slot))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*slotJournal){
		func(j *slotJournal) { j.Nonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
		func(j *slotJournal) { j.ParentIdentity += "different" },
		func(j *slotJournal) { j.AnchorIno++ },
		func(j *slotJournal) { j.CgroupIno++ },
	} {
		candidate := initial
		mutate(&candidate)
		if err := prepareNetwork(context.Background(), baseFD, slot, owner, &candidate, f); err == nil {
			t.Fatal("accepted mismatched binding")
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("journal changed", err)
	}
	if len(f.events) != 0 {
		t.Fatal("adapter invoked")
	}
}

func TestNetworkCleanupStaleSnapshotAndJournalErrors(t *testing.T) {
	for _, mode := range []string{"stale", "missing", "corrupt", "pending", "kill-failure"} {
		t.Run(mode, func(t *testing.T) {
			base, baseFD, groupFD, slot, owner, stale, f := networkFixture(t)
			active := stale
			if err := prepareNetwork(context.Background(), baseFD, slot, owner, &active, f); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(base, journalName(slot))
			switch mode {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "pending":
				if err := os.WriteFile(filepath.Join(base, journalTempName(slot)), []byte("partial"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			killed := false
			f.events = nil
			kill := func(int, time.Duration) error {
				killed = true
				if mode == "kill-failure" {
					return errors.New("kill failed")
				}
				f.killed = true
				return nil
			}
			var adapter networkResourceAdapter
			if mode == "kill-failure" {
				adapter = cleanupFake{f}
			}
			// Missing adapter ensures stale state cannot release a recorded network.
			if err := cleanupSlotWithNetwork(baseFD, groupFD, slot, stale, owner, kill, adapter); err == nil {
				t.Fatal("cleanup unexpectedly succeeded")
			}
			if !killed {
				t.Fatal("verified cgroup not killed")
			}
			if len(f.events) != 0 {
				t.Fatal("resource removed")
			}
			if mode != "missing" {
				if _, err := os.Stat(path); err != nil {
					t.Fatal("journal removed", err)
				}
			}
			if _, err := os.Stat(filepath.Join(base, anchorName(slot))); err != nil {
				t.Fatal("anchor removed", err)
			}
		})
	}
}

func TestNetworkVethIndicesAreNamespaceScoped(t *testing.T) {
	_, _, _, _, _, j, _ := networkFixture(t)
	p := generatedNetworkPlan(j)
	o := networkObject{Kind: "veth", HostIndex: 9, PeerIndex: 9, HostMAC: p.HostMAC, PeerMAC: p.PeerMAC}
	if !validNetworkObject(o, "veth", p) {
		t.Fatal("equal namespace-local indices rejected")
	}
	for _, bad := range []networkObject{
		{Kind: "veth", HostIndex: 0, PeerIndex: 9, HostMAC: p.HostMAC, PeerMAC: p.PeerMAC},
		{Kind: "veth", HostIndex: 9, PeerIndex: -1, HostMAC: p.HostMAC, PeerMAC: p.PeerMAC},
		{Kind: "veth", HostIndex: 9, PeerIndex: 9, HostMAC: "bad", PeerMAC: p.PeerMAC},
	} {
		if validNetworkObject(bad, "veth", p) {
			t.Fatalf("accepted %+v", bad)
		}
	}
}
