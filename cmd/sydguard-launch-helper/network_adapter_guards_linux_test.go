//go:build linux

package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestManagedNetworkAdapterRejectsUnverifiedLease(t *testing.T) {
	for _, kind := range []string{"binding", "object", "non-cloexec", "wrong-fd"} {
		t.Run(kind, func(t *testing.T) {
			f := newAdapterNativeFixture(t)
			original := f.a.callbacks.lease
			f.a.callbacks.lease = func(ctx context.Context, b namespaceLeaseBinding, o networkObject, fd *os.File) (namespaceLeaseResult, error) {
				result, err := original(ctx, b, o, fd)
				if err != nil {
					return result, err
				}
				switch kind {
				case "binding":
					result.Binding.Nonce = "wrong"
				case "object":
					result.Object.Ino++
				case "non-cloexec":
					if _, err = unix.FcntlInt(result.FD.Fd(), unix.F_SETFD, 0); err != nil {
						t.Fatal(err)
					}
				case "wrong-fd":
					result.FD.Close()
					result.FD, err = os.Open("/dev/null")
					if err != nil {
						t.Fatal(err)
					}
				}
				return result, nil
			}
			if err := f.prepare(context.Background()); err == nil {
				t.Fatal("invalid lease accepted")
			}
			j, ok, err := readJournal(f.base, f.slot, f.owner)
			if err != nil || !ok || j.Network.State != "recorded" || len(j.Network.Objects) != 1 {
				t.Fatalf("bad journal after rejected lease: %+v %v", j.Network, err)
			}
			if len(f.events) != 2 || f.events[1] != "lease" {
				t.Fatalf("later side effects: %v", f.events)
			}
		})
	}
}
func TestManagedNetworkAdapterActivationGuardsBeforeAddressing(t *testing.T) {
	for _, kind := range []string{"cookie", "firewall", "veth-index", "veth-mac", "collision"} {
		t.Run(kind, func(t *testing.T) {
			f := newAdapterNativeFixture(t)
			switch kind {
			case "cookie":
				f.a.ops.hostCookie = func(context.Context, int, networkObject) (uint64, error) {
					return f.a.listeners.namespaceCookie ^ 1, nil
				}
			case "firewall":
				f.firewall++
			case "collision":
				f.fail = "collision"
			case "veth-index", "veth-mac":
				original := f.a.ops.createVeth
				f.a.ops.createVeth = func(ctx context.Context, p networkPlan, h int, hn networkObject, n int, nn networkObject) (networkObject, error) {
					o, err := original(ctx, p, h, hn, n, nn)
					if kind == "veth-index" {
						f.host.Index++
					} else {
						f.peer.HardwareAddr[5] ^= 1
					}
					return o, err
				}
			}
			if err := f.prepare(context.Background()); err == nil {
				t.Fatal("invalid activation accepted")
			}
			j, ok, err := readJournal(f.base, f.slot, f.owner)
			if err != nil || !ok || j.Network.State != "activating" {
				t.Fatalf("activation not quarantined: %+v %v", j.Network, err)
			}
			for _, event := range f.events {
				if strings.HasPrefix(event, "addr:") || strings.HasPrefix(event, "up:") || strings.HasPrefix(event, "route:") {
					t.Fatalf("activation side effect after guard failure: %v", f.events)
				}
			}
		})
	}
}
