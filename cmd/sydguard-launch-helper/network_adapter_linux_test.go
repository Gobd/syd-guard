//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"testing"
)

type leaseOrderFake struct {
	*fakeNetworkResources
	called bool
}

func (f *leaseOrderFake) namespaceRecorded(ctx context.Context, o networkObject) error {
	j := f.journal("recorded")
	if len(j.Network.Objects) != 1 || j.Network.Objects[0] != o {
		f.t.Fatal("namespace lease preceded durable record")
	}
	f.called = true
	return errors.New("lease rejected")
}
func TestPrepareNetworkRecordsNamespaceBeforeLease(t *testing.T) {
	_, base, _, slot, owner, j, f := networkFixture(t)
	a := &leaseOrderFake{fakeNetworkResources: f}
	if err := prepareNetwork(context.Background(), base, slot, owner, &j, a); err == nil {
		t.Fatal("lease failure accepted")
	}
	if !a.called || len(f.events) != 1 || f.events[0] != "create:namespace" {
		t.Fatalf("later side effects: %v", f.events)
	}
	current, exists, err := readJournal(base, slot, owner)
	if err != nil || !exists || current.Network.State != "recorded" || len(current.Network.Objects) != 1 {
		t.Fatalf("namespace not recorded: %+v %v", current.Network, err)
	}
}
func TestManagedNetworkAdapterRequiresLeaseBeforeCreationOrActivation(t *testing.T) {
	called := false
	a := &managedNetworkAdapter{callbacks: namespaceLeaseCallbacks{recover: func(context.Context, namespaceLeaseBinding, networkObject) (namespaceLeaseResult, error) {
		called = true
		return namespaceLeaseResult{}, nil
	}}}
	if err := a.ensureLease(context.Background(), networkObject{Kind: "namespace"}, false); err == nil || called {
		t.Fatal("unacknowledged lease accepted or recovered during creation")
	}
}
func TestManagedNetworkAdapterRejectsUnknownRecoveryDescriptor(t *testing.T) {
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	a := &managedNetworkAdapter{callbacks: namespaceLeaseCallbacks{recover: func(context.Context, namespaceLeaseBinding, networkObject) (namespaceLeaseResult, error) {
		return namespaceLeaseResult{FD: f}, nil
	}}}
	if err := a.ensureLease(context.Background(), networkObject{Kind: "namespace", Dev: 1, Ino: 1}, true); err == nil {
		t.Fatal("unknown descriptor accepted")
	}
	if _, err = f.Stat(); err == nil {
		t.Fatal("rejected descriptor not closed")
	}
}
