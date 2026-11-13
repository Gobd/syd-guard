//go:build linux

package main

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func networkPrefixMessage(kind uint16, bits byte, attr uint16, address [4]byte) syscall.NetlinkMessage {
	size := unix.SizeofRtMsg
	if kind == unix.RTM_NEWADDR {
		size = unix.SizeofIfAddrmsg
	}
	data := make([]byte, size+8)
	data[0], data[1] = unix.AF_INET, bits
	binary.NativeEndian.PutUint16(data[size:size+2], 8)
	binary.NativeEndian.PutUint16(data[size+2:size+4], attr)
	copy(data[size+4:], address[:])
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: kind}, Data: data}
}

func TestNetworkCollisionMessagePrefixes(t *testing.T) {
	target := netip.MustParsePrefix("10.232.7.16/30")
	cases := []struct {
		msg     syscall.NetlinkMessage
		overlap bool
		invalid bool
	}{
		{networkPrefixMessage(unix.RTM_NEWROUTE, 16, unix.RTA_DST, [4]byte{10, 232, 0, 0}), true, false},
		{networkPrefixMessage(unix.RTM_NEWROUTE, 32, unix.RTA_DST, [4]byte{10, 232, 7, 17}), true, false},
		{networkPrefixMessage(unix.RTM_NEWROUTE, 24, unix.RTA_DST, [4]byte{10, 232, 8, 0}), false, false},
		{networkPrefixMessage(unix.RTM_NEWROUTE, 0, unix.RTA_DST, [4]byte{}), false, false},
		{networkPrefixMessage(unix.RTM_NEWADDR, 24, unix.IFA_LOCAL, [4]byte{10, 232, 7, 99}), true, false},
		{networkPrefixMessage(unix.RTM_NEWADDR, 32, unix.IFA_ADDRESS, [4]byte{127, 0, 0, 1}), false, false},
		{networkPrefixMessage(unix.RTM_NEWROUTE, 33, unix.RTA_DST, [4]byte{10, 232, 7, 16}), false, true},
		{syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWROUTE}, Data: []byte{unix.AF_INET}}, false, true},
		{networkPrefixMessage(unix.RTM_NEWADDR, 24, unix.IFA_LABEL, [4]byte{10, 232, 7, 1}), false, true},
	}
	for i, tc := range cases {
		got, err := networkMessageOverlaps(tc.msg, target)
		if (err != nil) != tc.invalid || err == nil && got != tc.overlap {
			t.Fatalf("case %d: overlap=%t err=%v", i, got, err)
		}
	}
}
