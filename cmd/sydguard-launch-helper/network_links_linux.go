//go:build linux

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"runtime"
	"time"

	rtnl "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// createAnonymousNetworkNamespace runs on a disposable locked thread. Go
// destroys that thread when the goroutine exits without UnlockOSThread, so no
// altered namespace is returned to the scheduler's pool. No bind mount/name
// exists. The caller must durably record and independently lease the returned
// CLOEXEC FD to the watchdog before connecting or activating any link.
func createAnonymousNetworkNamespace(ctx context.Context) (int, networkObject, error) {
	if err := ctx.Err(); err != nil {
		return -1, networkObject{}, err
	}
	if os.Geteuid() != 0 {
		return -1, networkObject{}, errors.New("network namespace creation requires fixed root helper")
	}
	type result struct {
		fd     int
		object networkObject
		err    error
	}
	done := make(chan result)
	go func() {
		runtime.LockOSThread() // deliberately not unlocked: discard this thread
		r := result{fd: -1}
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			r.err = err
		} else {
			r.fd, r.err = unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if r.err == nil {
				var st unix.Stat_t
				r.err = unix.Fstat(r.fd, &st)
				r.object = networkObject{Kind: "namespace", Dev: st.Dev, Ino: st.Ino}
				if r.err == nil {
					r.err = verifyNetworkNamespaceFD(r.fd, r.object)
				}
			}
		}
		if r.err != nil && r.fd >= 0 {
			unix.Close(r.fd)
			r.fd = -1
		}
		select {
		case done <- r:
		case <-ctx.Done():
			if r.fd >= 0 {
				unix.Close(r.fd)
			}
		}
	}()
	select {
	case r := <-done:
		if err := ctx.Err(); err != nil {
			if r.fd >= 0 {
				unix.Close(r.fd)
			}
			return -1, networkObject{}, err
		}
		return r.fd, r.object, r.err
	case <-ctx.Done():
		return -1, networkObject{}, ctx.Err()
	}
}

// routeSocket is private to one transaction; closing it interrupts blocked I/O.
type routeSocket interface {
	Close()
	LinkByName(string) (rtnl.Link, error)
	LinkByIndex(int) (rtnl.Link, error)
	LinkAdd(rtnl.Link) error
	LinkDel(rtnl.Link) error
	AddrAdd(rtnl.Link, *rtnl.Addr) error
	RouteAdd(*rtnl.Route) error
	LinkSetUp(rtnl.Link) error
}

type managedRoute struct {
	ctx    context.Context
	socket routeSocket
	stop   chan struct{}
	done   chan struct{}
}

func newManagedRoute(ctx context.Context, socket routeSocket) *managedRoute {
	r := &managedRoute{ctx: ctx, socket: socket, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(r.done)
		select {
		case <-ctx.Done():
			socket.Close()
		case <-r.stop:
		}
	}()
	return r
}

func (r *managedRoute) Close() {
	close(r.stop)
	<-r.done
	r.socket.Close()
}

func (r *managedRoute) result(err error) error {
	if e := r.ctx.Err(); e != nil {
		return e
	}
	return err
}
func (r *managedRoute) LinkByName(name string) (rtnl.Link, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	link, err := r.socket.LinkByName(name)
	return link, r.result(err)
}
func (r *managedRoute) LinkByIndex(index int) (rtnl.Link, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	link, err := r.socket.LinkByIndex(index)
	return link, r.result(err)
}
func (r *managedRoute) LinkAdd(link rtnl.Link) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	return r.result(r.socket.LinkAdd(link))
}
func (r *managedRoute) LinkDel(link rtnl.Link) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	return r.result(r.socket.LinkDel(link))
}

func (r *managedRoute) AddrAdd(link rtnl.Link, addr *rtnl.Addr) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	return r.result(r.socket.AddrAdd(link, addr))
}

func (r *managedRoute) RouteAdd(route *rtnl.Route) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	return r.result(r.socket.RouteAdd(route))
}

func (r *managedRoute) LinkSetUp(link rtnl.Link) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	return r.result(r.socket.LinkSetUp(link))
}

// The borrowed descriptor must remain open until duplication completes.
func duplicateRouteNamespace(fd int, object networkObject) (int, error) {
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return -1, err
	}
	if err := verifyNetworkNamespaceFD(dup, object); err != nil {
		unix.Close(dup)
		return -1, err
	}
	return dup, nil
}

func managedRouteHandle(ctx context.Context, fd int, object networkObject) (*managedRoute, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dup, err := duplicateRouteNamespace(fd, object)
	if err != nil {
		return nil, err
	}
	return openRouteOnDisposableThread(ctx, dup, unix.Setns, func() (routeSocket, error) {
		return rtnl.NewHandle(unix.NETLINK_ROUTE)
	})
}

// Takes ownership of fd. Never unlock the outer thread, including on errors:
// no library namespace entry or restoration callback is involved.
func openRouteOnDisposableThread(ctx context.Context, fd int, setns func(int, int) error, open func() (routeSocket, error)) (*managedRoute, error) {
	type result struct {
		socket routeSocket
		err    error
	}
	done := make(chan result)
	go func() {
		runtime.LockOSThread()
		defer unix.Close(fd)
		var r result
		r.err = setns(fd, unix.CLONE_NEWNET)
		if r.err == nil {
			r.socket, r.err = open()
		}
		if r.err != nil && r.socket != nil {
			r.socket.Close()
			r.socket = nil
		}
		select {
		case done <- r:
		case <-ctx.Done():
			if r.socket != nil {
				r.socket.Close()
			}
		}
	}()
	select {
	case r := <-done:
		if err := ctx.Err(); err != nil {
			if r.socket != nil {
				r.socket.Close()
			}
			return nil, err
		}
		if r.err != nil {
			return nil, r.err
		}
		return newManagedRoute(ctx, r.socket), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func generatedLinkMAC(value string) (net.HardwareAddr, error) {
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != 6 || b[0]&3 != 2 {
		return nil, errors.New("invalid generated link MAC")
	}
	return net.HardwareAddr(b), nil
}

func verifyManagedLinkPair(p networkPlan, o networkObject, host, peer rtnl.Link) error {
	if !validNetworkObject(o, "veth", p) || host == nil || peer == nil || host.Type() != "veth" || peer.Type() != "veth" {
		return errors.New("invalid managed veth identity")
	}
	h, a := host.Attrs(), peer.Attrs()
	if h.Index != o.HostIndex || a.Index != o.PeerIndex || h.Name != p.HostLink || a.Name != p.PeerLink || hex.EncodeToString(h.HardwareAddr) != o.HostMAC || hex.EncodeToString(a.HardwareAddr) != o.PeerMAC || h.ParentIndex != a.Index || a.ParentIndex != h.Index {
		return errors.New("managed veth identity or peer relationship changed")
	}
	return nil
}

// Links are created DOWN, atomically placing the peer in the pinned anonymous
// namespace. Firewall installation and watchdog lease ACK precede activation.
func createManagedVeth(ctx context.Context, p networkPlan, hostFD int, hostNS networkObject, peerFD int, peerNS networkObject) (networkObject, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if !validManagedNFTName(p.Table) || p.HostLink != "sgh"+p.Table[3:] || p.PeerLink != "sga"+p.Table[3:] {
		return networkObject{}, errors.New("invalid generated link names")
	}
	hostMAC, err := generatedLinkMAC(p.HostMAC)
	if err != nil {
		return networkObject{}, err
	}
	peerMAC, err := generatedLinkMAC(p.PeerMAC)
	if err != nil {
		return networkObject{}, err
	}
	// Keep this verified duplicate alive through LinkAdd, which serializes its FD.
	peerDup, err := duplicateRouteNamespace(peerFD, peerNS)
	if err != nil {
		return networkObject{}, err
	}
	defer unix.Close(peerDup)
	h, err := managedRouteHandle(ctx, hostFD, hostNS)
	if err != nil {
		return networkObject{}, err
	}
	defer h.Close()
	a, err := managedRouteHandle(ctx, peerDup, peerNS)
	if err != nil {
		return networkObject{}, err
	}
	defer a.Close()
	// An unexpected lookup failure is not evidence of absence.
	for _, check := range []struct {
		handle *managedRoute
		name   string
	}{{h, p.HostLink}, {a, p.PeerLink}} {
		_, err := check.handle.LinkByName(check.name)
		var missing rtnl.LinkNotFoundError
		if !errors.As(err, &missing) {
			return networkObject{}, errors.Join(errors.New("link collision or uncertain lookup"), err)
		}
	}
	if err := ctx.Err(); err != nil {
		return networkObject{}, err
	}
	link := &rtnl.Veth{LinkAttrs: rtnl.LinkAttrs{Name: p.HostLink, HardwareAddr: hostMAC}, PeerName: p.PeerLink, PeerHardwareAddr: peerMAC, PeerNamespace: rtnl.NsFd(peerDup)}
	if err := h.LinkAdd(link); err != nil {
		return networkObject{}, err
	}
	hl, err := h.LinkByName(p.HostLink)
	if err != nil {
		return networkObject{}, err
	}
	pl, err := a.LinkByName(p.PeerLink)
	if err != nil {
		return networkObject{}, err
	}
	o := networkObject{Kind: "veth", HostIndex: hl.Attrs().Index, PeerIndex: pl.Attrs().Index, HostMAC: p.HostMAC, PeerMAC: p.PeerMAC}
	if err := verifyManagedLinkPair(p, o, hl, pl); err != nil {
		return networkObject{}, err
	}
	if hl.Attrs().Flags&net.FlagUp != 0 || pl.Attrs().Flags&net.FlagUp != 0 {
		return networkObject{}, errors.New("new veth unexpectedly active")
	}
	if err := ctx.Err(); err != nil {
		return networkObject{}, err
	}
	return o, nil
}

func deleteManagedVeth(ctx context.Context, p networkPlan, o networkObject, hostFD int, hostNS networkObject, peerFD int, peerNS networkObject) error {
	return deleteManagedVethWithRoutes(ctx, p, o, hostFD, hostNS, peerFD, peerNS, managedRouteHandle)
}

func deleteManagedVethWithRoutes(ctx context.Context, p networkPlan, o networkObject, hostFD int, hostNS networkObject, peerFD int, peerNS networkObject, open func(context.Context, int, networkObject) (*managedRoute, error)) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	h, err := open(ctx, hostFD, hostNS)
	if err != nil {
		return err
	}
	defer h.Close()
	a, err := open(ctx, peerFD, peerNS)
	if err != nil {
		return err
	}
	defer a.Close()
	hl, err := h.LinkByIndex(o.HostIndex)
	if err != nil {
		return err
	}
	pl, err := a.LinkByIndex(o.PeerIndex)
	if err != nil {
		return err
	}
	if err := verifyManagedLinkPair(p, o, hl, pl); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// RTM_DELLINK is index-scoped, not a reopen/delete by display name.
	return h.LinkDel(hl)
}
