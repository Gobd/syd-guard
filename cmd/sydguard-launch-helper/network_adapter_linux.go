//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"time"

	rtnl "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// A successful lease callback is a trusted root-coordinator assertion, not
// proof of a watchdog ACK. The real watchdog has no lease loop; production
// wiring requires an authenticated peer-retention ACK channel first.
type namespaceLeaseBinding struct {
	UID                  uint32
	Index                int
	Nonce                string
	ParentPID            int
	ParentIdentity       string
	AnchorDev, AnchorIno uint64
}
type namespaceLeaseResult struct {
	Binding namespaceLeaseBinding
	Object  networkObject
	FD      *os.File
}

// The lease callback owns the supplied CLOEXEC duplicate even on error. The
// returned descriptor transfers to the adapter; recovery likewise transfers it.
type namespaceLeaseCallbacks struct {
	lease   func(context.Context, namespaceLeaseBinding, networkObject, *os.File) (namespaceLeaseResult, error)
	recover func(context.Context, namespaceLeaseBinding, networkObject) (namespaceLeaseResult, error)
	release func(context.Context, namespaceLeaseBinding, networkObject) error
}

func leaseBinding(j slotJournal) namespaceLeaseBinding {
	return namespaceLeaseBinding{j.UID, j.Index, j.Nonce, j.ParentPID, j.ParentIdentity, j.AnchorDev, j.AnchorIno}
}

type managedNetworkAdapter struct {
	baseFD, anchorFD, hostFD int
	host                     networkObject
	slot                     *launchSlot
	owner                    uint32
	binding                  namespaceLeaseBinding
	listeners                *networkListeners
	callbacks                namespaceLeaseCallbacks
	ops                      networkAdapterOps
	namespace                *os.File
	lease                    *os.File
	namespaceObject          networkObject
}

// The caller keeps borrowed descriptors and listeners alive until their
// verified duplicates have been acquired by this constructor.
func newManagedNetworkAdapter(baseFD, anchorFD, hostFD int, host networkObject, slot *launchSlot, owner uint32, j slotJournal, listeners *networkListeners, callbacks namespaceLeaseCallbacks) (*managedNetworkAdapter, error) {
	if slot == nil || owner != 0 || callbacks.lease == nil || callbacks.recover == nil || callbacks.release == nil || listeners == nil || validateJournal(slot, j) != nil || j.Phase != "ready" {
		return nil, errors.New("invalid root network adapter binding")
	}
	dup := func(fd int) (int, error) { return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3) }
	b, err := dup(baseFD)
	if err != nil {
		return nil, err
	}
	a, err := dup(anchorFD)
	if err != nil {
		unix.Close(b)
		return nil, err
	}
	h, err := duplicateRouteNamespace(hostFD, host)
	if err != nil {
		unix.Close(b)
		unix.Close(a)
		return nil, err
	}
	x := &managedNetworkAdapter{baseFD: b, anchorFD: a, hostFD: h, host: host, slot: slot, owner: owner, binding: leaseBinding(j), callbacks: callbacks, ops: nativeNetworkAdapterOps()}
	fail := func(err error) (*managedNetworkAdapter, error) { x.Close(); return nil, err }
	var bs, as unix.Stat_t
	if err = unix.Fstat(b, &bs); err != nil {
		return fail(err)
	}
	if err = unix.Fstat(a, &as); err != nil {
		return fail(err)
	}
	if bs.Mode&unix.S_IFMT != unix.S_IFDIR || bs.Uid != 0 || bs.Mode&0022 != 0 || as.Mode&unix.S_IFMT != unix.S_IFDIR || as.Uid != 0 || as.Mode&0022 != 0 || as.Dev != j.AnchorDev || as.Ino != j.AnchorIno {
		return fail(errors.New("unsafe root network directories"))
	}
	current, exists, err := readJournal(b, slot, owner)
	if err != nil || !exists || !reflect.DeepEqual(current, j) {
		return fail(errors.New("stale network adapter journal"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cookie, err := x.ops.hostCookie(ctx, h, host)
	if err != nil || cookie == 0 {
		return fail(errors.New("cannot verify host network namespace cookie"))
	}
	x.listeners, err = duplicateNetworkListeners(generatedNetworkPlan(j), listeners, cookie)
	if err != nil {
		return fail(err)
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	return x, nil
}
func (a *managedNetworkAdapter) Close() {
	if a.listeners != nil {
		a.listeners.Close()
		a.listeners = nil
	}
	if a.namespace != nil {
		_ = a.namespace.Close()
		a.namespace = nil
	}
	if a.lease != nil {
		_ = a.lease.Close()
		a.lease = nil
	}
	for _, fd := range []int{a.baseFD, a.anchorFD, a.hostFD} {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
	a.baseFD = -1
	a.anchorFD = -1
	a.hostFD = -1
}
func (a *managedNetworkAdapter) verifyAnchor() error {
	var held, named unix.Stat_t
	if err := unix.Fstat(a.anchorFD, &held); err != nil {
		return err
	}
	if err := unix.Fstatat(a.baseFD, anchorName(a.slot), &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if held.Mode&unix.S_IFMT != unix.S_IFDIR || held.Uid != a.owner || held.Mode&0022 != 0 || held.Dev != a.binding.AnchorDev || held.Ino != a.binding.AnchorIno || named.Dev != held.Dev || named.Ino != held.Ino || named.Mode&unix.S_IFMT != unix.S_IFDIR || named.Uid != a.owner || named.Mode&0022 != 0 {
		return errors.New("network anchor identity changed")
	}
	return nil
}
func (a *managedNetworkAdapter) journal(p networkPlan, state string) (slotJournal, error) {
	j, ok, err := readJournal(a.baseFD, a.slot, a.owner)
	if err != nil || !ok || leaseBinding(j) != a.binding || j.Network == nil || j.Network.State != state || generatedNetworkPlan(j) != p {
		return slotJournal{}, errors.New("network journal binding changed")
	}
	return j, nil
}
func verifyLeaseResult(r namespaceLeaseResult, b namespaceLeaseBinding, o networkObject) error {
	if r.FD == nil || r.Binding != b || r.Object != o {
		return errors.New("network lease binding mismatch")
	}
	flags, err := unix.FcntlInt(r.FD.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		return errors.New("network lease is not CLOEXEC")
	}
	return verifyNetworkNamespaceFD(int(r.FD.Fd()), o)
}
func (a *managedNetworkAdapter) namespaceRecorded(ctx context.Context, o networkObject) error {
	p := generatedNetworkPlan(slotJournal{UID: a.binding.UID, Index: a.binding.Index, Nonce: a.binding.Nonce})
	j, err := a.journal(p, "recorded")
	if err != nil || len(j.Network.Objects) != 1 || j.Network.Objects[0] != o || a.namespace == nil || a.namespaceObject != o {
		return errors.New("namespace not durably recorded")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	fd, err := duplicateRouteNamespace(int(a.namespace.Fd()), o)
	if err != nil {
		return err
	}
	r, err := a.callbacks.lease(ctx, a.binding, o, os.NewFile(uintptr(fd), "namespace-lease-transfer"))
	if err == nil {
		err = verifyLeaseResult(r, a.binding, o)
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		if r.FD != nil {
			_ = r.FD.Close()
		}
		return err
	}
	a.lease = r.FD
	return nil
}
func (a *managedNetworkAdapter) ensureLease(ctx context.Context, o networkObject, recovery bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.lease == nil {
		if !recovery {
			return errors.New("namespace lease ACK required")
		}
		r, err := a.callbacks.recover(ctx, a.binding, o)
		if err == nil {
			err = verifyLeaseResult(r, a.binding, o)
		}
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			if r.FD != nil {
				_ = r.FD.Close()
			}
			return errors.Join(errors.New("network lease unavailable; quarantining"), err)
		}
		a.lease = r.FD
	}
	return verifyLeaseResult(namespaceLeaseResult{a.binding, o, a.lease}, a.binding, o)
}

const resolverName = "resolv.conf"

func resolverBytes(p networkPlan) []byte { return []byte("nameserver " + p.Host.String() + "\n") }
func (a *managedNetworkAdapter) createResolver(ctx context.Context, p networkPlan) (networkObject, error) {
	if err := ctx.Err(); err != nil {
		return networkObject{}, err
	}
	fd, err := unix.Openat(a.anchorFD, resolverName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return networkObject{}, err
	}
	f := os.NewFile(uintptr(fd), "network-resolver")
	defer f.Close()
	if err = unix.Fchmod(fd, 0600); err != nil {
		return networkObject{}, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return networkObject{}, err
	}
	if st.Uid != a.owner || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return networkObject{}, errors.New("unsafe resolver")
	}
	if err = ctx.Err(); err != nil {
		return networkObject{}, err
	}
	n, err := f.Write(resolverBytes(p))
	if err != nil {
		return networkObject{}, err
	}
	if n != len(resolverBytes(p)) {
		return networkObject{}, io.ErrShortWrite
	}
	if err = f.Sync(); err != nil {
		return networkObject{}, err
	}
	if err = f.Close(); err != nil {
		return networkObject{}, err
	}
	if err = ctx.Err(); err != nil {
		return networkObject{}, err
	}
	if err = unix.Fsync(a.anchorFD); err != nil {
		return networkObject{}, err
	}
	if err = ctx.Err(); err != nil {
		return networkObject{}, err
	}
	return networkObject{Kind: "resolver", Dev: st.Dev, Ino: st.Ino}, nil
}
func (a *managedNetworkAdapter) Create(ctx context.Context, p networkPlan, kind string) (networkObject, error) {
	if err := ctx.Err(); err != nil {
		return networkObject{}, err
	}
	if err := verifyNetworkNamespaceFD(a.hostFD, a.host); err != nil {
		return networkObject{}, err
	}
	if err := a.verifyAnchor(); err != nil {
		return networkObject{}, err
	}
	j, err := a.journal(p, "creating")
	if err != nil {
		return networkObject{}, err
	}
	if len(j.Network.Objects) >= len(networkKinds) || networkKinds[len(j.Network.Objects)] != kind {
		return networkObject{}, errors.New("unexpected network creation")
	}
	if err = ctx.Err(); err != nil {
		return networkObject{}, err
	}
	if kind != "namespace" {
		if err = a.ensureLease(ctx, j.Network.Objects[0], false); err != nil {
			return networkObject{}, err
		}
	}
	switch kind {
	case "namespace":
		if a.namespace != nil || a.lease != nil {
			return networkObject{}, errors.New("namespace already exists")
		}
		fd, o, err := a.ops.createNamespace(ctx)
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
			return networkObject{}, err
		}
		flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if flagErr != nil || flags&unix.FD_CLOEXEC == 0 {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
			return networkObject{}, errors.New("namespace descriptor is not CLOEXEC")
		}
		if err = verifyNetworkNamespaceFD(fd, o); err != nil {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
			return networkObject{}, err
		}
		a.namespace = os.NewFile(uintptr(fd), "network-namespace")
		a.namespaceObject = o
		return o, nil
	case "resolver":
		return a.ops.createResolver(ctx, a, p)
	case "firewall":
		return a.ops.installFirewall(ctx, a.baseFD, a.slot, a.owner, j, a.hostFD, a.host, a.listeners)
	case "veth":
		return a.ops.createVeth(ctx, p, a.hostFD, a.host, int(a.lease.Fd()), j.Network.Objects[0])
	}
	return networkObject{}, errors.New("unknown network resource")
}
func (a *managedNetworkAdapter) Activate(ctx context.Context, p networkPlan, objects []networkObject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifyNetworkNamespaceFD(a.hostFD, a.host); err != nil {
		return err
	}
	if err := a.verifyAnchor(); err != nil {
		return err
	}
	j, err := a.journal(p, "activating")
	if err != nil || !reflect.DeepEqual(j.Network.Objects, objects) || len(objects) != 4 {
		return errors.New("invalid activation journal")
	}
	if err = a.ensureLease(ctx, objects[0], false); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	cookie, err := a.ops.hostCookie(ctx, a.hostFD, a.host)
	if err != nil {
		return err
	}
	if _, _, err = firewallPorts(p, a.listeners, cookie); err != nil {
		return err
	}
	handle, err := a.ops.lookupFirewall(ctx, a.hostFD, a.host, p.Table)
	if err != nil || handle != objects[2].Handle {
		return errors.Join(errors.New("firewall identity changed"), err)
	}
	h, err := a.ops.openRoute(ctx, a.hostFD, a.host)
	if err != nil {
		return err
	}
	defer h.Close()
	peer, err := a.ops.openRoute(ctx, int(a.lease.Fd()), objects[0])
	if err != nil {
		return err
	}
	defer peer.Close()
	hl, err := h.LinkByIndex(objects[3].HostIndex)
	if err != nil {
		return err
	}
	pl, err := peer.LinkByIndex(objects[3].PeerIndex)
	if err != nil {
		return err
	}
	if err = verifyManagedLinkPair(p, objects[3], hl, pl); err != nil {
		return err
	}
	if hl.Attrs().Flags&net.FlagUp != 0 || pl.Attrs().Flags&net.FlagUp != 0 {
		return errors.New("veth already active")
	}
	if err = a.ops.collision(ctx, p, a.hostFD, a.host); err != nil {
		return err
	}
	hostAddr := &rtnl.Addr{IPNet: &net.IPNet{IP: net.IP(p.Host.AsSlice()), Mask: net.CIDRMask(30, 32)}}
	peerAddr := &rtnl.Addr{IPNet: &net.IPNet{IP: net.IP(p.Agent.AsSlice()), Mask: net.CIDRMask(30, 32)}}
	if err = h.AddrAdd(hl, hostAddr); err != nil {
		return err
	}
	if err = peer.AddrAdd(pl, peerAddr); err != nil {
		return err
	}
	if err = h.LinkSetUp(hl); err != nil {
		return err
	}
	if err = peer.LinkSetUp(pl); err != nil {
		return err
	}
	_, dst, _ := net.ParseCIDR("198.18.0.0/15")
	if err = peer.RouteAdd(&rtnl.Route{LinkIndex: objects[3].PeerIndex, Dst: dst, Gw: net.IP(p.Host.AsSlice())}); err != nil {
		return err
	}
	hl, err = h.LinkByIndex(objects[3].HostIndex)
	if err != nil {
		return err
	}
	pl, err = peer.LinkByIndex(objects[3].PeerIndex)
	if err != nil {
		return err
	}
	if err = verifyManagedLinkPair(p, objects[3], hl, pl); err != nil {
		return err
	}
	if hl.Attrs().Flags&net.FlagUp == 0 || pl.Attrs().Flags&net.FlagUp == 0 {
		return errors.New("veth activation incomplete")
	}
	if err = a.ensureLease(ctx, objects[0], false); err != nil {
		return err
	}
	handle, err = a.ops.lookupFirewall(ctx, a.hostFD, a.host, p.Table)
	if err != nil || handle != objects[2].Handle {
		return errors.Join(errors.New("firewall identity changed during activation"), err)
	}
	current, err := a.journal(p, "activating")
	if err != nil || !reflect.DeepEqual(current.Network.Objects, objects) {
		return errors.New("activation journal changed")
	}
	return ctx.Err()
}
func (a *managedNetworkAdapter) RemoveIfIdentityMatches(ctx context.Context, p networkPlan, o networkObject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifyNetworkNamespaceFD(a.hostFD, a.host); err != nil {
		return err
	}
	if err := a.verifyAnchor(); err != nil {
		return err
	}
	j, ok, err := readJournal(a.baseFD, a.slot, a.owner)
	if err != nil || !ok || leaseBinding(j) != a.binding || j.Network == nil || j.Network.State != "deleting" || generatedNetworkPlan(j) != p || len(j.Network.Objects) == 0 || j.Network.Objects[len(j.Network.Objects)-1] != o {
		return errors.New("invalid network cleanup binding")
	}
	if err = a.ensureLease(ctx, j.Network.Objects[0], true); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	switch o.Kind {
	case "veth":
		return a.ops.deleteVeth(ctx, p, o, a.hostFD, a.host, int(a.lease.Fd()), j.Network.Objects[0])
	case "firewall":
		return a.ops.deleteFirewall(ctx, a.hostFD, a.host, p.Table, o.Handle)
	case "resolver":
		fd, err := unix.Openat(a.anchorFD, resolverName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), "resolver-check")
		defer f.Close()
		var st, named unix.Stat_t
		if err = unix.Fstat(fd, &st); err != nil {
			return err
		}
		if st.Dev != o.Dev || st.Ino != o.Ino || st.Uid != a.owner || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Nlink != 1 {
			return errors.New("resolver identity changed")
		}
		data, err := io.ReadAll(io.LimitReader(f, 256))
		if err != nil || !bytes.Equal(data, resolverBytes(p)) {
			return errors.New("resolver bytes changed")
		}
		if err = unix.Fstatat(a.anchorFD, resolverName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if named.Dev != o.Dev || named.Ino != o.Ino {
			return errors.New("resolver name changed")
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = unix.Unlinkat(a.anchorFD, resolverName, 0); err != nil {
			return err
		}
		if err = unix.Fsync(a.anchorFD); err != nil {
			return err
		}
		return ctx.Err()
	case "namespace":
		if err = a.callbacks.release(ctx, a.binding, o); err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if a.namespace != nil {
			_ = a.namespace.Close()
			a.namespace = nil
		}
		if a.lease != nil {
			_ = a.lease.Close()
			a.lease = nil
		}
		return nil
	}
	return fmt.Errorf("unknown network resource %q", o.Kind)
}

var _ networkResourceAdapter = (*managedNetworkAdapter)(nil)
