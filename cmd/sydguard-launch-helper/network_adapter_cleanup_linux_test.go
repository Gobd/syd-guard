//go:build linux

package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestManagedNetworkAdapterDeletionFailureRemainsPending(t *testing.T) {
	for _, event := range []string{"delete:veth", "delete:firewall", "release:namespace"} {
		t.Run(event, func(t *testing.T) {
			f := newAdapterNativeFixture(t)
			if err := f.prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.fail = event
			if err := cleanupSlotWithNetwork(f.base, f.group, f.slot, f.j, f.owner, func(int, time.Duration) error { return nil }, f.a); err == nil {
				t.Fatal("ambiguous deletion succeeded")
			}
			j, ok, err := readJournal(f.base, f.slot, f.owner)
			if err != nil || !ok || j.Network == nil || j.Network.State != "deleting" {
				t.Fatalf("deletion was not quarantined: %+v %v", j.Network, err)
			}
			before := f.deleted
			if err = cleanupSlotWithNetwork(f.base, f.group, f.slot, j, f.owner, func(int, time.Duration) error { return nil }, f.a); err == nil {
				t.Fatal("ambiguous deletion retried")
			}
			if f.deleted != before {
				t.Fatal("second deletion attempted")
			}
		})
	}
}
func TestManagedNetworkAdapterNoCleanupWithoutKill(t *testing.T) {
	f := newAdapterNativeFixture(t)
	if err := f.prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := cleanupSlotWithNetwork(f.base, f.group, f.slot, f.j, f.owner, func(int, time.Duration) error { return errors.New("kill failed") }, f.a); err == nil {
		t.Fatal("failed kill accepted")
	}
	if f.deleted != 0 {
		t.Fatal("network removed after failed kill")
	}
	j, ok, err := readJournal(f.base, f.slot, f.owner)
	if err != nil || !ok || j.Network.State != "active" {
		t.Fatalf("journal changed after failed kill: %+v %v", j.Network, err)
	}
}
func TestManagedNetworkAdapterCanceledCleanupDoesNotDelete(t *testing.T) {
	f := newAdapterNativeFixture(t)
	if err := f.prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.a.RemoveIfIdentityMatches(ctx, generatedNetworkPlan(f.j), f.j.Network.Objects[3]); !errors.Is(err, context.Canceled) {
		t.Fatalf("cleanup: %v", err)
	}
	if f.deleted != 0 {
		t.Fatal("canceled cleanup deleted resource")
	}
}
