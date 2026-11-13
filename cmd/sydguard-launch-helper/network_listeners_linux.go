//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// networkListeners stay in the control network namespace. They are prebound to
// a root-generated address with IP_FREEBIND before the veth address exists.
// The future broker must authenticate the FD roles before accepting traffic.
type networkListeners struct {
	dnsTCP          *net.TCPListener
	dnsUDP          *net.UDPConn
	gateway         *net.TCPListener
	namespaceCookie uint64
}

func (l *networkListeners) Close() {
	if l == nil {
		return
	}
	if l.dnsTCP != nil {
		_ = l.dnsTCP.Close()
	}
	if l.dnsUDP != nil {
		_ = l.dnsUDP.Close()
	}
	if l.gateway != nil {
		_ = l.gateway.Close()
	}
}

func freebindControl(_, _ string, raw syscall.RawConn) error {
	var sockErr error
	if err := raw.Control(func(fd uintptr) { sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_FREEBIND, 1) }); err != nil {
		return err
	}
	return sockErr
}

func networkSocketCookie(socket syscall.Conn) (uint64, error) {
	raw, err := socket.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cookie uint64
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cookie, sockErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	}); err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, sockErr
	}
	if cookie == 0 {
		return 0, errors.New("invalid socket network namespace cookie")
	}
	return cookie, nil
}

// duplicateNetworkListeners owns independent socket descriptors. The caller
// must keep each borrowed listener open until its File duplication completes.
func duplicateNetworkListeners(p networkPlan, borrowed *networkListeners, hostCookie uint64) (_ *networkListeners, err error) {
	if borrowed == nil || borrowed.dnsTCP == nil || borrowed.dnsUDP == nil || borrowed.gateway == nil {
		return nil, errors.New("missing prebound listeners")
	}
	owned := &networkListeners{namespaceCookie: hostCookie}
	defer func() {
		if err != nil {
			owned.Close()
		}
	}()
	copyTCP := func(source *net.TCPListener) (*net.TCPListener, error) {
		f, err := source.File()
		if err != nil {
			return nil, err
		}
		l, err := net.FileListener(f)
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			l.Close()
			return nil, closeErr
		}
		tcp, ok := l.(*net.TCPListener)
		if !ok {
			l.Close()
			return nil, errors.New("not a TCP listener")
		}
		return tcp, nil
	}
	if owned.dnsTCP, err = copyTCP(borrowed.dnsTCP); err != nil {
		return nil, err
	}
	f, err := borrowed.dnsUDP.File()
	if err != nil {
		return nil, err
	}
	packet, err := net.FilePacketConn(f)
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		packet.Close()
		return nil, closeErr
	}
	var ok bool
	owned.dnsUDP, ok = packet.(*net.UDPConn)
	if !ok {
		packet.Close()
		return nil, errors.New("not a UDP socket")
	}
	if owned.gateway, err = copyTCP(borrowed.gateway); err != nil {
		return nil, err
	}
	if _, _, err = firewallPorts(p, owned, hostCookie); err != nil {
		return nil, err
	}
	for _, s := range []struct {
		socket                   syscall.Conn
		typ, protocol, accepting int
	}{
		{owned.dnsTCP, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1},
		{owned.dnsUDP, unix.SOCK_DGRAM, unix.IPPROTO_UDP, 0},
		{owned.gateway, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1},
	} {
		raw, e := s.socket.SyscallConn()
		if e != nil {
			return nil, e
		}
		var check error
		if e = raw.Control(func(fd uintptr) {
			flags, e := unix.FcntlInt(fd, unix.F_GETFD, 0)
			if e != nil || flags&unix.FD_CLOEXEC == 0 {
				check = errors.New("prebound socket is not CLOEXEC")
				return
			}
			for _, v := range []struct{ opt, want int }{{unix.SO_DOMAIN, unix.AF_INET}, {unix.SO_TYPE, s.typ}, {unix.SO_PROTOCOL, s.protocol}, {unix.SO_ACCEPTCONN, s.accepting}} {
				got, e := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, v.opt)
				if e != nil || got != v.want {
					check = fmt.Errorf("prebound socket role mismatch: option %d got %d want %d: %v", v.opt, got, v.want, e)
					return
				}
			}
			if s.typ == unix.SOCK_DGRAM {
				if _, e := unix.Getpeername(int(fd)); !errors.Is(e, unix.ENOTCONN) {
					check = errors.New("UDP socket is connected or uncertain")
				}
			}
		}); e != nil {
			return nil, e
		}
		if check != nil {
			return nil, check
		}
	}
	return owned, nil
}

// prebindNetworkListeners requires the locked root launch thread to still be in
// its original host network namespace. The current namespace is checked via a
// separate socket cookie; root must authenticate and retain these FDs itself.
func prebindNetworkListeners(ctx context.Context, baseFD int, slot *launchSlot, owner uint32, expected slotJournal) (*networkListeners, error) {
	return prebindNetworkListenersWithBind(ctx, baseFD, slot, owner, expected, bindNetworkListeners)
}

// The binder is private to the operation; production always uses native sockets.
func prebindNetworkListenersWithBind(ctx context.Context, baseFD int, slot *launchSlot, owner uint32, expected slotJournal, bind func(context.Context, networkPlan) (*networkListeners, error)) (*networkListeners, error) {
	if slot == nil {
		return nil, errors.New("missing launch slot")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := lockNetworkLifecycle(ctx, slot); err != nil {
		return nil, err
	}
	defer slot.lifecycleMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if validateJournal(slot, expected) != nil || expected.Phase != "ready" || expected.Network != nil {
		return nil, errors.New("invalid listener launch binding")
	}
	current, exists, readErr := readJournal(baseFD, slot, owner)
	if readErr != nil || !exists || !reflect.DeepEqual(current, expected) {
		return nil, errors.New("listener launch journal is stale")
	}
	return bind(ctx, generatedNetworkPlan(current))
}

func bindNetworkListeners(ctx context.Context, p networkPlan) (_ *networkListeners, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: freebindControl}
	lc.SetMultipathTCP(false)
	reference, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	cookie, err := networkSocketCookie(reference)
	_ = reference.Close()
	if err != nil {
		return nil, err
	}
	listeners := &networkListeners{namespaceCookie: cookie}
	defer func() {
		if err != nil {
			listeners.Close()
		}
	}()
	address := net.JoinHostPort(p.Host.String(), "0")
	tcp, err := lc.Listen(ctx, "tcp4", address)
	if err != nil {
		return nil, err
	}
	var ok bool
	listeners.dnsTCP, ok = tcp.(*net.TCPListener)
	if !ok {
		_ = tcp.Close()
		return nil, errors.New("unexpected DNS TCP listener")
	}
	dnsAddress, ok := listeners.dnsTCP.Addr().(*net.TCPAddr)
	if !ok || dnsAddress == nil || dnsAddress.Port <= 0 || dnsAddress.AddrPort().Addr() != p.Host {
		return nil, errors.New("invalid DNS bind address")
	}
	udp, err := lc.ListenPacket(ctx, "udp4", net.JoinHostPort(p.Host.String(), strconv.Itoa(dnsAddress.Port)))
	if err != nil {
		return nil, err
	}
	listeners.dnsUDP, ok = udp.(*net.UDPConn)
	if !ok {
		_ = udp.Close()
		return nil, errors.New("unexpected DNS UDP socket")
	}
	gateway, err := lc.Listen(ctx, "tcp4", address)
	if err != nil {
		return nil, err
	}
	listeners.gateway, ok = gateway.(*net.TCPListener)
	if !ok {
		_ = gateway.Close()
		return nil, errors.New("unexpected gateway listener")
	}
	udpAddress, ok := listeners.dnsUDP.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddress == nil || udpAddress.AddrPort() != dnsAddress.AddrPort() || listeners.dnsUDP.RemoteAddr() != nil {
		return nil, errors.New("invalid DNS UDP bind address")
	}
	gatewayAddress, ok := listeners.gateway.Addr().(*net.TCPAddr)
	if !ok || gatewayAddress == nil || gatewayAddress.AddrPort().Addr() != p.Host || gatewayAddress.Port <= 0 || gatewayAddress.Port == dnsAddress.Port {
		return nil, errors.New("invalid gateway bind address")
	}
	for _, s := range []syscall.Conn{listeners.dnsTCP, listeners.dnsUDP, listeners.gateway} {
		actual, e := networkSocketCookie(s)
		if e != nil || actual != cookie {
			return nil, fmt.Errorf("socket network namespace mismatch: %w", e)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return listeners, nil
}

func (l *networkListeners) addresses() (netip.AddrPort, netip.AddrPort) {
	return l.dnsTCP.Addr().(*net.TCPAddr).AddrPort(), l.gateway.Addr().(*net.TCPAddr).AddrPort()
}
