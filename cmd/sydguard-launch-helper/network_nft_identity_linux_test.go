//go:build linux

package main

import (
	"encoding/binary"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func nftIdentityReply(t *testing.T, attrs []netlink.Attribute) []netlink.Message {
	t.Helper()
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		t.Fatal(err)
	}
	return []netlink.Message{{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWTABLE)}, Data: append([]byte{managedNFTFamily, 0, 0, 0}, b...)}}
}

func TestManagedNFTIdentity(t *testing.T) {
	name := "sg_0123456789ab"
	h := make([]byte, 8)
	binary.BigEndian.PutUint64(h, 0x0123456789abcdef)
	attrs := []netlink.Attribute{{Type: unix.NFTA_TABLE_NAME, Data: []byte(name + "\x00")}, {Type: nftTableHandle | unix.NLA_F_NET_BYTEORDER, Data: h}}
	reply := nftIdentityReply(t, attrs)
	got, err := managedNFTTableHandle(reply, name)
	if err != nil || got != 0x0123456789abcdef {
		t.Fatalf("identity: %x %v", got, err)
	}
	for _, bad := range []string{"", "sg_0123456789AB", "other_table", "sg_0123456789ab\x00"} {
		if _, err := managedNFTGetMessage(bad); err == nil {
			t.Fatalf("accepted name %q", bad)
		}
	}
	if _, err := managedNFTTableHandle(reply, "sg_aaaaaaaaaaaa"); err == nil {
		t.Fatal("accepted substituted name")
	}
	if _, err := managedNFTTableHandle(append(reply, reply...), name); err == nil {
		t.Fatal("accepted multiple tables")
	}
	if _, err := managedNFTTableHandle(nftIdentityReply(t, append(attrs, attrs[1])), name); err == nil {
		t.Fatal("accepted duplicate handle")
	}
	for _, value := range [][]byte{nil, {1}, make([]byte, 8)} {
		bad := []netlink.Attribute{attrs[0], {Type: nftTableHandle, Data: value}}
		if _, err := managedNFTTableHandle(nftIdentityReply(t, bad), name); err == nil {
			t.Fatal("accepted malformed/zero handle")
		}
	}
	reply[0].Data[0] = unix.AF_INET
	if _, err := managedNFTTableHandle(reply, name); err == nil {
		t.Fatal("accepted wrong family")
	}
}

func TestManagedNFTDeleteUsesHandleOnly(t *testing.T) {
	if _, err := managedNFTDeleteBatch(0); err == nil {
		t.Fatal("accepted zero/unbound handle")
	}
	batch, err := managedNFTDeleteBatch(777)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 3 || batch[0].Header.Type != unix.NFNL_MSG_BATCH_BEGIN || batch[2].Header.Type != unix.NFNL_MSG_BATCH_END {
		t.Fatal("not atomic nft batch")
	}
	m := batch[1]
	if m.Header.Type != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_DELTABLE) || m.Data[0] != managedNFTFamily {
		t.Fatal("wrong deletion/family")
	}
	attrs, err := netlink.UnmarshalAttributes(m.Data[4:])
	if err != nil || len(attrs) != 1 || attrs[0].Type&0x3fff != nftTableHandle || binary.BigEndian.Uint64(attrs[0].Data) != 777 {
		t.Fatalf("unbound deletion: %v %v", attrs, err)
	}
	if m.Header.Flags&netlink.Acknowledge == 0 {
		t.Fatal("missing ACK request")
	}
	// No NAME attribute: concurrent same-name replacement cannot change the
	// kernel handle lookup target. Never permit an empty-family flush request.
	if len(m.Data) <= 4 {
		t.Fatal("empty deletion flushes family")
	}
}
