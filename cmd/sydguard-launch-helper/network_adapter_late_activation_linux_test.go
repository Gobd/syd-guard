//go:build linux

package main

import (
	"context"
	"errors"
	"testing"

	rtnl "github.com/vishvananda/netlink"
)

type latePeerRouteSocket struct {
	*adapterRouteSocket
	calls    *int
	mismatch bool
}

func (s *latePeerRouteSocket) LinkByIndex(i int) (rtnl.Link, error) {
	*s.calls++
	if *s.calls == 2 {
		if !s.mismatch {
			return nil, errors.New("late peer lookup failed")
		}
		s.f.peer.HardwareAddr[5] ^= 1
	}
	return s.adapterRouteSocket.LinkByIndex(i)
}
func TestManagedNetworkAdapterFinalActivationChecksQuarantine(t *testing.T) {
	for _, kind := range []string{"final-firewall-error", "final-firewall-identity", "final-peer-error", "final-peer-identity"} {
		t.Run(kind, func(t *testing.T) {
			f := newAdapterNativeFixture(t)
			calls := 0
			switch kind {
			case "final-firewall-error":
				f.fail = "lookup:firewall"
				f.failAt = 2
			case "final-firewall-identity":
				original := f.a.ops.lookupFirewall
				f.a.ops.lookupFirewall = func(ctx context.Context, fd int, o networkObject, name string) (uint64, error) {
					calls++
					h, err := original(ctx, fd, o, name)
					if calls == 2 {
						h++
					}
					return h, err
				}
			case "final-peer-error", "final-peer-identity":
				f.a.ops.openRoute = func(ctx context.Context, fd int, _ networkObject) (*managedRoute, error) {
					base := &adapterRouteSocket{f: f, host: fd == f.a.hostFD}
					if base.host {
						return newManagedRoute(ctx, base), nil
					}
					return newManagedRoute(ctx, &latePeerRouteSocket{adapterRouteSocket: base, calls: &calls, mismatch: kind == "final-peer-identity"}), nil
				}
			}
			if err := f.prepare(context.Background()); err == nil {
				t.Fatal("late failure accepted")
			}
			j, ok, err := readJournal(f.base, f.slot, f.owner)
			if err != nil || !ok || j.Network == nil || j.Network.State != "activating" {
				t.Fatalf("late failure not quarantined: %+v %v", j.Network, err)
			}
			if f.deleted != 0 {
				t.Fatal("late failure triggered guessed cleanup")
			}
			route := false
			for _, e := range f.events {
				if e == "route:peer" {
					route = true
				}
			}
			if !route {
				t.Fatal("failed before final checks")
			}
			if kind == "final-firewall-error" && f.failSeen != 2 {
				t.Fatalf("firewall lookup occurrence %d", f.failSeen)
			}
			if kind != "final-firewall-error" && calls != 2 {
				t.Fatalf("check occurrence %d", calls)
			}
		})
	}
}
