//go:build linux

package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// originalDestination reads Linux's conntrack SO_ORIGINAL_DST on an nft REDIRECT
// TCP socket. The fixed-size standard-library helper provides sufficient storage
// for sockaddr_in; this does not add unsafe code or a packet stack.
func originalDestination(conn *net.TCPConn) (netip.AddrPort, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var result netip.AddrPort
	var socketErr error
	err = raw.Control(func(fd uintptr) {
		const soOriginalDST = 80
		value, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, soOriginalDST)
		if err != nil {
			socketErr = err
			return
		}
		data := value.Multiaddr
		if binary.NativeEndian.Uint16(data[:2]) != syscall.AF_INET {
			socketErr = fmt.Errorf("expected IPv4 original destination")
			return
		}
		address := netip.AddrFrom4([4]byte{data[4], data[5], data[6], data[7]})
		result = netip.AddrPortFrom(address, binary.BigEndian.Uint16(data[2:4]))
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	return result, socketErr
}
