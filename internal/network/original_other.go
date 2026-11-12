//go:build !linux

package network

import (
	"fmt"
	"net"
	"net/netip"
)

func originalDestination(_ *net.TCPConn) (netip.AddrPort, error) {
	return netip.AddrPort{}, fmt.Errorf("transparent interception runs in Linux")
}
