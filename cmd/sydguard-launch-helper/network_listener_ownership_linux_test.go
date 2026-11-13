//go:build linux

package main

import (
	"context"
	"os"
	"testing"
)

func TestDuplicateNetworkListenersOwnsSockets(t *testing.T) {
	_, base, _, slot, owner, j, _ := networkFixture(t)
	borrowed, err := prebindNetworkListeners(context.Background(), base, slot, owner, j)
	if err != nil {
		t.Fatal(err)
	}
	defer borrowed.Close()
	p := generatedNetworkPlan(j)
	owned, err := duplicateNetworkListeners(p, borrowed, borrowed.namespaceCookie)
	if err != nil {
		t.Fatal(err)
	}
	if owned.dnsTCP == borrowed.dnsTCP || owned.dnsUDP == borrowed.dnsUDP || owned.gateway == borrowed.gateway {
		t.Fatal("borrowed listener returned")
	}
	owned.Close()
	if _, _, err = firewallPorts(p, borrowed, borrowed.namespaceCookie); err != nil {
		t.Fatalf("closing owned closed original: %v", err)
	}
	owned, err = duplicateNetworkListeners(p, borrowed, borrowed.namespaceCookie)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close()
	borrowed.Close()
	if _, _, err = firewallPorts(p, owned, owned.namespaceCookie); err != nil {
		t.Fatalf("closing original closed owned: %v", err)
	}
}
func TestDuplicateNetworkListenersRejectsWrongCookieWithoutClosingOriginals(t *testing.T) {
	_, base, _, slot, owner, j, _ := networkFixture(t)
	borrowed, err := prebindNetworkListeners(context.Background(), base, slot, owner, j)
	if err != nil {
		t.Fatal(err)
	}
	defer borrowed.Close()
	p := generatedNetworkPlan(j)
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if got, err := duplicateNetworkListeners(p, borrowed, borrowed.namespaceCookie^1); err == nil {
			got.Close()
			t.Fatal("wrong namespace cookie accepted")
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatalf("rejected conversions leaked descriptors: %d -> %d: %v", len(before), len(after), err)
	}
	if got, err := duplicateNetworkListeners(p, borrowed, borrowed.namespaceCookie^1); err == nil {
		got.Close()
		t.Fatal("wrong namespace cookie accepted")
	}
	if _, _, err := firewallPorts(p, borrowed, borrowed.namespaceCookie); err != nil {
		t.Fatalf("rejected duplication closed borrowed: %v", err)
	}
	wrong := p
	wrong.Host = wrong.Host.Next()
	if got, err := duplicateNetworkListeners(wrong, borrowed, borrowed.namespaceCookie); err == nil {
		got.Close()
		t.Fatal("wrong bound address accepted")
	}
	if _, _, err := firewallPorts(p, borrowed, borrowed.namespaceCookie); err != nil {
		t.Fatalf("rejected duplication closed borrowed: %v", err)
	}
}
