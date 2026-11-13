//go:build linux

package main

import (
	"context"
	"net"
	"testing"
)

func TestRootGeneratedPreboundNetworkListeners(t *testing.T) {
	_, baseFD, _, slot, owner, j, _ := networkFixture(t)
	listeners, err := prebindNetworkListeners(context.Background(), baseFD, slot, owner, j)
	if err != nil {
		t.Fatal(err)
	}
	defer listeners.Close()
	dns, gateway := listeners.addresses()
	plan := generatedNetworkPlan(j)
	if dns.Addr() != plan.Host || gateway.Addr() != plan.Host || dns.Port() == 0 || gateway.Port() == 0 || dns.Port() == gateway.Port() || listeners.namespaceCookie == 0 {
		t.Fatalf("invalid bound listeners: %v %v", dns, gateway)
	}
	if listeners.dnsUDP.LocalAddr().(*net.UDPAddr).AddrPort() != dns {
		t.Fatal("DNS addresses differ")
	}
}

func TestRootGeneratedPreboundNetworkListenersRejectStaleAndCanceled(t *testing.T) {
	_, baseFD, _, slot, owner, j, _ := networkFixture(t)
	stale := j
	stale.AnchorIno++
	if l, err := prebindNetworkListeners(context.Background(), baseFD, slot, owner, stale); err == nil {
		l.Close()
		t.Fatal("stale journal accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if l, err := prebindNetworkListeners(ctx, baseFD, slot, owner, j); err == nil {
		l.Close()
		t.Fatal("canceled bind accepted")
	}
}
