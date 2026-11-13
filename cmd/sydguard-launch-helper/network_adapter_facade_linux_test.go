//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	rtnl "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type adapterNativeFixture struct {
	t           *testing.T
	a           *managedNetworkAdapter
	base, group int
	slot        *launchSlot
	owner       uint32
	j           slotJournal
	events      []string
	fail        string
	failAt      int
	failSeen    int
	cancel      context.CancelFunc
	host, peer  *rtnl.Veth
	firewall    uint64
	deleted     int
}

func (f *adapterNativeFixture) step(name string) error {
	f.events = append(f.events, name)
	if f.fail == name {
		f.failSeen++
		if f.failAt > 0 && f.failSeen != f.failAt {
			return nil
		}
		if f.cancel != nil {
			f.cancel()
			return nil
		}
		return errors.New("injected partial failure")
	}
	return nil
}

type adapterRouteSocket struct {
	f    *adapterNativeFixture
	host bool
}

func (s *adapterRouteSocket) Close() {}
func (s *adapterRouteSocket) LinkByName(string) (rtnl.Link, error) {
	return nil, errors.New("unexpected name lookup")
}
func (s *adapterRouteSocket) LinkByIndex(i int) (rtnl.Link, error) {
	l := s.f.peer
	if s.host {
		l = s.f.host
	}
	if l == nil || l.Attrs().Index != i {
		return nil, errors.New("index not found")
	}
	return l, nil
}
func (s *adapterRouteSocket) LinkAdd(rtnl.Link) error { return errors.New("unexpected add") }
func (s *adapterRouteSocket) LinkDel(rtnl.Link) error { s.f.deleted++; return s.f.step("delete:veth") }
func (s *adapterRouteSocket) AddrAdd(link rtnl.Link, addr *rtnl.Addr) error {
	p := generatedNetworkPlan(s.f.j)
	expected, index := p.Agent, 14
	if s.host {
		expected, index = p.Host, 13
	}
	if link == nil || link.Attrs().Index != index || addr == nil || addr.IPNet == nil || !addr.IP.Equal(net.IP(expected.AsSlice())) {
		s.f.t.Fatal("wrong link or generated address")
	}
	bits, width := addr.Mask.Size()
	if bits != 30 || width != 32 {
		s.f.t.Fatal("wrong transit mask")
	}
	if s.host {
		return s.f.step("addr:host")
	}
	return s.f.step("addr:peer")
}
func (s *adapterRouteSocket) RouteAdd(route *rtnl.Route) error {
	p := generatedNetworkPlan(s.f.j)
	if s.host || route == nil || route.LinkIndex != 14 || route.Dst == nil || route.Dst.String() != "198.18.0.0/15" || !route.Gw.Equal(net.IP(p.Host.AsSlice())) {
		s.f.t.Fatal("wrong private peer route")
	}
	return s.f.step("route:peer")
}
func (s *adapterRouteSocket) LinkSetUp(l rtnl.Link) error {
	l.Attrs().Flags |= net.FlagUp
	if s.host {
		return s.f.step("up:host")
	}
	return s.f.step("up:peer")
}
func newAdapterNativeFixture(t *testing.T) *adapterNativeFixture {
	t.Helper()
	_, base, group, slot, owner, j, _ := networkFixture(t)
	l, err := prebindNetworkListeners(context.Background(), base, slot, owner, j)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	owned, err := duplicateNetworkListeners(generatedNetworkPlan(j), l, l.namespaceCookie)
	if err != nil {
		t.Fatal(err)
	}
	dup := func(fd int) int {
		d, e := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
		if e != nil {
			t.Fatal(e)
		}
		return d
	}
	anchor, err := unix.Openat(base, anchorName(slot), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	hostFD, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err = unix.Fstat(hostFD, &st); err != nil {
		t.Fatal(err)
	}
	hostNS := networkObject{Kind: "namespace", Dev: st.Dev, Ino: st.Ino}
	f := &adapterNativeFixture{t: t, base: base, group: group, slot: slot, owner: owner, j: j, firewall: 42}
	a := &managedNetworkAdapter{baseFD: dup(base), anchorFD: anchor, hostFD: hostFD, host: hostNS, slot: slot, owner: owner, binding: leaseBinding(j), listeners: owned}
	f.a = a
	t.Cleanup(a.Close)
	a.callbacks = namespaceLeaseCallbacks{
		lease: func(ctx context.Context, b namespaceLeaseBinding, o networkObject, fd *os.File) (namespaceLeaseResult, error) {
			j, ok, err := readJournal(base, slot, owner)
			if err != nil || !ok || j.Network.State != "recorded" || len(j.Network.Objects) != 1 || j.Network.Objects[0] != o {
				t.Fatal("lease before durable namespace")
			}
			if err = f.step("lease"); err != nil {
				fd.Close()
				return namespaceLeaseResult{}, err
			}
			return namespaceLeaseResult{b, o, fd}, nil
		},
		recover: func(context.Context, namespaceLeaseBinding, networkObject) (namespaceLeaseResult, error) {
			return namespaceLeaseResult{}, errors.New("missing recovery lease")
		},
		release: func(context.Context, namespaceLeaseBinding, networkObject) error { return f.step("release:namespace") },
	}
	a.ops = nativeNetworkAdapterOps()
	a.ops.createNamespace = func(ctx context.Context) (int, networkObject, error) {
		fd, e := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if e != nil {
			return -1, networkObject{}, e
		}
		e = f.step("create:namespace")
		return fd, hostNS, e
	}
	a.ops.createResolver = func(ctx context.Context, a *managedNetworkAdapter, p networkPlan) (networkObject, error) {
		o, e := a.createResolver(ctx, p)
		if e != nil {
			return o, e
		}
		return o, f.step("create:resolver")
	}
	a.ops.installFirewall = func(ctx context.Context, _ int, _ *launchSlot, _ uint32, j slotJournal, _ int, _ networkObject, listeners *networkListeners) (networkObject, error) {
		if j.Network.State != "creating" || len(j.Network.Objects) != 2 {
			t.Fatal("firewall not pending")
		}
		if _, _, err := firewallPorts(generatedNetworkPlan(j), listeners, owned.namespaceCookie); err != nil {
			t.Fatal(err)
		}
		return networkObject{Kind: "firewall", Handle: 42}, f.step("create:firewall")
	}
	a.ops.createVeth = func(ctx context.Context, p networkPlan, _ int, _ networkObject, _ int, _ networkObject) (networkObject, error) {
		hm, _ := generatedLinkMAC(p.HostMAC)
		pm, _ := generatedLinkMAC(p.PeerMAC)
		f.host = &rtnl.Veth{LinkAttrs: rtnl.LinkAttrs{Index: 13, ParentIndex: 14, Name: p.HostLink, HardwareAddr: hm}}
		f.peer = &rtnl.Veth{LinkAttrs: rtnl.LinkAttrs{Index: 14, ParentIndex: 13, Name: p.PeerLink, HardwareAddr: pm}}
		return networkObject{Kind: "veth", HostIndex: 13, PeerIndex: 14, HostMAC: p.HostMAC, PeerMAC: p.PeerMAC}, f.step("create:veth")
	}
	a.ops.hostCookie = func(ctx context.Context, _ int, _ networkObject) (uint64, error) {
		if e := f.step("cookie"); e != nil {
			return 0, e
		}
		return owned.namespaceCookie, nil
	}
	a.ops.lookupFirewall = func(ctx context.Context, _ int, _ networkObject, _ string) (uint64, error) {
		if e := f.step("lookup:firewall"); e != nil {
			return 0, e
		}
		return f.firewall, nil
	}
	a.ops.openRoute = func(ctx context.Context, fd int, _ networkObject) (*managedRoute, error) {
		return newManagedRoute(ctx, &adapterRouteSocket{f: f, host: fd == a.hostFD}), nil
	}
	a.ops.collision = func(ctx context.Context, _ networkPlan, _ int, _ networkObject) error { return f.step("collision") }
	a.ops.deleteVeth = func(ctx context.Context, p networkPlan, o networkObject, h int, hn networkObject, n int, nn networkObject) error {
		return deleteManagedVethWithRoutes(ctx, p, o, h, hn, n, nn, a.ops.openRoute)
	}
	a.ops.deleteFirewall = func(ctx context.Context, _ int, _ networkObject, _ string, h uint64) error {
		if h != f.firewall {
			return errors.New("firewall handle replaced")
		}
		f.deleted++
		return f.step("delete:firewall")
	}
	return f
}
func (f *adapterNativeFixture) prepare(ctx context.Context) error {
	return prepareNetwork(ctx, f.base, f.slot, f.owner, &f.j, f.a)
}
func TestManagedNetworkAdapterConcreteLifecycle(t *testing.T) {
	f := newAdapterNativeFixture(t)
	if err := f.prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"create:namespace", "lease", "create:resolver", "create:firewall", "create:veth", "cookie", "lookup:firewall", "collision", "addr:host", "addr:peer", "up:host", "up:peer", "route:peer", "lookup:firewall"}
	if !reflect.DeepEqual(f.events, want) {
		t.Fatalf("order %v", f.events)
	}
	kill := func(int, time.Duration) error { return f.step("kill") }
	if err := cleanupSlotWithNetwork(f.base, f.group, f.slot, f.j, f.owner, kill, f.a); err != nil {
		t.Fatal(err)
	}
	want = append(want, "kill", "delete:veth", "delete:firewall", "release:namespace")
	if !reflect.DeepEqual(f.events, want) {
		t.Fatalf("cleanup order %v", f.events)
	}
}
func TestManagedNetworkAdapterConcretePartialAndCanceledQuarantine(t *testing.T) {
	for _, event := range []string{"create:namespace", "lease", "create:resolver", "create:firewall", "create:veth", "cookie", "lookup:firewall", "collision", "addr:host", "addr:peer", "up:host", "up:peer", "route:peer"} {
		for _, cancel := range []bool{false, true} {
			t.Run(event+map[bool]string{false: "-error", true: "-cancel"}[cancel], func(t *testing.T) {
				f := newAdapterNativeFixture(t)
				ctx, stop := context.WithCancel(context.Background())
				defer stop()
				f.fail = event
				if cancel {
					f.cancel = stop
				}
				if err := f.prepare(ctx); err == nil {
					t.Fatal("partial operation succeeded")
				}
				j, ok, err := readJournal(f.base, f.slot, f.owner)
				if err != nil || !ok || j.Network == nil {
					t.Fatalf("journal: %+v %v", j, err)
				}
				want := "activating"
				switch event {
				case "create:namespace", "create:resolver", "create:firewall", "create:veth":
					want = "creating"
				case "lease":
					want = "recorded"
				}
				if j.Network.State != want {
					t.Fatalf("state %q want %q", j.Network.State, want)
				}
				if f.deleted != 0 {
					t.Fatal("partial setup guessed cleanup")
				}
			})
		}
	}
}
func TestManagedNetworkAdapterConcreteIdentityChangesQuarantine(t *testing.T) {
	for _, mutation := range []string{"host-index", "peer-index", "host-mac", "peer-mac", "firewall-handle", "resolver-inode", "resolver-bytes", "missing-recovery", "host-namespace-fd", "lease-fd", "anchor-inode"} {
		t.Run(mutation, func(t *testing.T) {
			f := newAdapterNativeFixture(t)
			if err := f.prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "host-index":
				f.host.Index++
			case "peer-index":
				f.peer.Index++
			case "host-mac":
				f.host.HardwareAddr[5] ^= 1
			case "peer-mac":
				f.peer.HardwareAddr[5] ^= 1
			case "firewall-handle":
				f.firewall++
			case "resolver-inode":
				if err := unix.Renameat(f.a.anchorFD, resolverName, f.a.anchorFD, "old-resolver"); err != nil {
					t.Fatal(err)
				}
				fd, err := unix.Openat(f.a.anchorFD, resolverName, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC, 0600)
				if err != nil {
					t.Fatal(err)
				}
				unix.Close(fd)
			case "resolver-bytes":
				fd, err := unix.Openat(f.a.anchorFD, resolverName, unix.O_WRONLY|unix.O_TRUNC|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				unix.Write(fd, []byte("replacement\n"))
				unix.Close(fd)
			case "missing-recovery":
				f.a.lease.Close()
				f.a.lease = nil
			case "host-namespace-fd":
				unix.Close(f.a.hostFD)
				fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				f.a.hostFD = fd
			case "anchor-inode":
				name := anchorName(f.slot)
				if err := unix.Renameat(f.base, name, f.base, name+"-replaced"); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkdirat(f.base, name, 0700); err != nil {
					t.Fatal(err)
				}
			case "lease-fd":
				f.a.lease.Close()
				file, err := os.Open("/dev/null")
				if err != nil {
					t.Fatal(err)
				}
				f.a.lease = file
			}
			err := cleanupSlotWithNetwork(f.base, f.group, f.slot, f.j, f.owner, func(int, time.Duration) error { return nil }, f.a)
			if err == nil {
				t.Fatal("identity replacement accepted")
			}
			// Earlier resources may have been safely removed before a later mismatch;
			// no deletion of the mismatched object is allowed.
			switch mutation {
			case "host-index", "peer-index", "host-mac", "peer-mac", "missing-recovery", "host-namespace-fd", "lease-fd", "anchor-inode":
				if f.deleted != 0 {
					t.Fatal("veth deleted after mismatch")
				}
			case "firewall-handle":
				if f.deleted != 1 {
					t.Fatal("firewall deleted after replacement")
				}
			case "resolver-inode", "resolver-bytes":
				fd, err := unix.Openat(f.a.anchorFD, resolverName, unix.O_RDONLY|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal("mismatched resolver deleted")
				}
				unix.Close(fd)
			}
		})
	}
}
