//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type fakeNetworkResources struct {
	t       *testing.T
	baseFD  int
	slot    *launchSlot
	owner   uint32
	objects map[string]networkObject
	events  []string
	fail    string
	killed  bool
}

func (f *fakeNetworkResources) journal(state string) slotJournal {
	f.t.Helper()
	j, exists, err := readJournal(f.baseFD, f.slot, f.owner)
	if err != nil || !exists || j.Network == nil || j.Network.State != state {
		f.t.Fatalf("journal state %s: %+v %v", state, j, err)
	}
	return j
}
func (f *fakeNetworkResources) Create(ctx context.Context, p networkPlan, kind string) (networkObject, error) {
	j := f.journal("creating")
	if generatedNetworkPlan(j) != p || kind != networkKinds[len(j.Network.Objects)] {
		f.t.Fatal("unbound create")
	}
	f.events = append(f.events, "create:"+kind)
	if err := ctx.Err(); err != nil {
		return networkObject{}, err
	}
	if f.fail == "create:"+kind {
		return networkObject{}, errors.New("collision or partial create")
	}
	o := networkObject{Kind: kind}
	switch kind {
	case "namespace":
		o.Dev, o.Ino = 1, 10
	case "resolver":
		o.Dev, o.Ino = 1, 11
	case "firewall":
		o.Handle = 12
	case "veth":
		o.HostIndex, o.PeerIndex, o.HostMAC, o.PeerMAC = 13, 14, p.HostMAC, p.PeerMAC
	default:
		f.t.Fatal("unexpected kind")
	}
	f.objects[kind] = o
	return o, nil
}
func (f *fakeNetworkResources) Activate(ctx context.Context, p networkPlan, objects []networkObject) error {
	j := f.journal("activating")
	if generatedNetworkPlan(j) != p || !reflect.DeepEqual(objects, j.Network.Objects) {
		f.t.Fatal("activation not journalled")
	}
	f.events = append(f.events, "activate")
	if f.fail == "activate" {
		return errors.New("partial activation")
	}
	return ctx.Err()
}
func (f *fakeNetworkResources) RemoveIfIdentityMatches(ctx context.Context, p networkPlan, object networkObject) error {
	if !f.killed {
		f.t.Fatal("network removed before cgroup kill")
	}
	j := f.journal("deleting")
	if len(j.Network.Objects) > 0 && j.Network.Objects[len(j.Network.Objects)-1] != object {
		f.t.Fatal("wrong cleanup order")
	}
	_ = p
	_ = ctx
	if f.objects[object.Kind] != object {
		return errors.New("resource identity changed")
	}
	f.events = append(f.events, "remove:"+object.Kind)
	delete(f.objects, object.Kind)
	return nil
}

// Cleanup records a pending deletion before each removal.
type cleanupFake struct{ *fakeNetworkResources }

func (f cleanupFake) RemoveIfIdentityMatches(ctx context.Context, p networkPlan, object networkObject) error {
	if !f.killed {
		f.t.Fatal("network removed before cgroup kill")
	}
	j, exists, err := readJournal(f.baseFD, f.slot, f.owner)
	if err != nil || !exists || j.Network == nil || j.Network.State != "deleting" || generatedNetworkPlan(j) != p || len(j.Network.Objects) == 0 || j.Network.Objects[len(j.Network.Objects)-1] != object {
		f.t.Fatal("bad cleanup journal")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.objects[object.Kind] != object {
		return errors.New("resource identity changed")
	}
	f.events = append(f.events, "remove:"+object.Kind)
	delete(f.objects, object.Kind)
	return nil
}

func networkFixture(t *testing.T) (string, int, int, *launchSlot, uint32, slotJournal, *fakeNetworkResources) {
	t.Helper()
	base, _, baseFD, groupFD, slot, owner := lifecycleFixture(t)
	j, group, err := prepareSlot(baseFD, groupFD, slot, "test-identity", owner, emptyCgroup)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Close(); err != nil {
		t.Fatal(err)
	}
	f := &fakeNetworkResources{t: t, baseFD: baseFD, slot: slot, owner: owner, objects: make(map[string]networkObject)}
	return base, baseFD, groupFD, slot, owner, j, f
}

func TestNetworkJournalPhaseAndKillBeforeIdentityCleanup(t *testing.T) {
	_, baseFD, groupFD, slot, owner, j, f := networkFixture(t)
	if err := prepareNetwork(context.Background(), baseFD, slot, owner, &j, f); err != nil {
		t.Fatal(err)
	}
	if j.Network.State != "active" {
		t.Fatal("network not active")
	}
	kill := func(int, time.Duration) error { f.killed = true; f.events = append(f.events, "kill"); return nil }
	if err := cleanupSlotWithNetwork(baseFD, groupFD, slot, j, owner, kill, cleanupFake{f}); err != nil {
		t.Fatal(err)
	}
	want := []string{"create:namespace", "create:resolver", "create:firewall", "create:veth", "activate", "kill", "remove:veth", "remove:firewall", "remove:resolver", "remove:namespace"}
	if !reflect.DeepEqual(f.events, want) {
		t.Fatalf("events %v", f.events)
	}
	if len(f.objects) != 0 {
		t.Fatal("objects remain")
	}
	if _, exists, err := readJournal(baseFD, slot, owner); err != nil || exists {
		t.Fatalf("journal remains: %t %v", exists, err)
	}
}

func TestNetworkJournalPartialCreateAndActivationQuarantined(t *testing.T) {
	for _, phase := range []string{"create:namespace", "create:resolver", "create:firewall", "create:veth", "activate"} {
		t.Run(phase, func(t *testing.T) {
			_, baseFD, groupFD, slot, owner, j, f := networkFixture(t)
			f.fail = phase
			if err := prepareNetwork(context.Background(), baseFD, slot, owner, &j, f); err == nil {
				t.Fatal("expected failure")
			}
			current, exists, err := readJournal(baseFD, slot, owner)
			if err != nil || !exists {
				t.Fatal("missing journal", err)
			}
			kill := func(int, time.Duration) error { f.killed = true; return nil }
			if err := cleanupSlotWithNetwork(baseFD, groupFD, slot, current, owner, kill, cleanupFake{f}); err == nil {
				t.Fatal("ambiguous phase cleaned")
			}
			if !f.killed {
				t.Fatal("cgroup not killed")
			}
			for _, event := range f.events {
				if len(event) >= 7 && event[:7] == "remove:" {
					t.Fatal("ambiguous object deleted")
				}
			}
		})
	}
}

func TestNetworkJournalIdentityReplacementAndNoAdapter(t *testing.T) {
	_, baseFD, groupFD, slot, owner, j, f := networkFixture(t)
	if err := prepareNetwork(context.Background(), baseFD, slot, owner, &j, f); err != nil {
		t.Fatal(err)
	}
	kill := func(int, time.Duration) error { f.killed = true; return nil }
	if err := cleanupSlot(baseFD, groupFD, slot, j, owner, kill); err == nil || !f.killed {
		t.Fatal("missing adapter did not kill and quarantine")
	}
	f.objects["veth"] = networkObject{Kind: "veth", HostIndex: 999}
	if err := cleanupSlotWithNetwork(baseFD, groupFD, slot, j, owner, kill, cleanupFake{f}); err == nil {
		t.Fatal("replaced veth removed")
	}
	if f.objects["veth"].HostIndex != 999 {
		t.Fatal("replacement deleted")
	}
}

func TestWatchdogRereadsNetworkJournalAndKillsOnCorruption(t *testing.T) {
	base, baseFD, groupFD, slot, owner, initial, f := networkFixture(t)
	j := initial
	if err := prepareNetwork(context.Background(), baseFD, slot, owner, &j, f); err != nil {
		t.Fatal(err)
	}
	killed := false
	kill := func(int, time.Duration) error { killed = true; return nil }
	if err := watchdogCleanup(baseFD, groupFD, slot, initial, owner, kill); err == nil || !killed {
		t.Fatal("watchdog used stale journal")
	}
	if _, err := os.Stat(filepath.Join(base, journalName(slot))); err != nil {
		t.Fatal("journal removed")
	}
	if err := os.WriteFile(filepath.Join(base, journalTempName(slot)), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	killed = false
	if err := watchdogCleanup(baseFD, groupFD, slot, initial, owner, kill); err == nil || !killed {
		t.Fatal("corrupt journal did not trigger kill")
	}
}

func TestNetworkJournalRejectsDuplicateAndIncompleteIdentities(t *testing.T) {
	_, baseFD, _, slot, owner, j, f := networkFixture(t)
	if err := prepareNetwork(context.Background(), baseFD, slot, owner, &j, f); err != nil {
		t.Fatal(err)
	}
	copyJournal := j
	copyNetwork := *j.Network
	copyNetwork.Objects = append([]networkObject(nil), j.Network.Objects...)
	copyJournal.Network = &copyNetwork
	copyNetwork.Objects[1].Dev = copyNetwork.Objects[0].Dev
	copyNetwork.Objects[1].Ino = copyNetwork.Objects[0].Ino
	if validateJournal(slot, copyJournal) == nil {
		t.Fatal("duplicate inode accepted")
	}
	copyNetwork.Objects = copyNetwork.Objects[:3]
	if validateJournal(slot, copyJournal) == nil {
		t.Fatal("incomplete active resources accepted")
	}
}

func TestNetworkPlanBoundToSlotAndNonce(t *testing.T) {
	_, _, _, _, _, j, _ := networkFixture(t)
	a := generatedNetworkPlan(j)
	j.Index++
	b := generatedNetworkPlan(j)
	if a == b || a.Host == a.Agent || len(a.HostLink) > 15 || len(a.PeerLink) > 15 {
		t.Fatalf("invalid generated plan: %+v %+v", a, b)
	}
}
