//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// The nftables library does not expose table handles. In particular, deleting a
// table by its display name would race a replacement. These operations use the
// kernel's NFTA_TABLE_HANDLE, scoped to an independently pinned host netns.
// Linux 6.8 nf_tables_deltable prioritizes HANDLE over NAME, and never flushes
// the whole family when a nonzero handle and explicit family are supplied.
const managedNFTFamily = 1 // NFPROTO_INET: includes IPv4 and IPv6 filtering.

// Linux v6.8 UAPI enum nft_table_attributes; x/sys currently exposes only the
// older NAME/FLAGS/USE attributes. Keep these wire numbers explicit and tested.
const (
	nftTableHandle   = 4
	nftTablePad      = 5
	nftTableUserdata = 6
	nftTableOwner    = 7
)

func validManagedNFTName(name string) bool {
	if len(name) != 15 || name[:3] != "sg_" {
		return false
	}
	return lowerHex(name[3:])
}

func lowerHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func managedNFTGetMessage(name string) (netlink.Message, error) {
	if !validManagedNFTName(name) {
		return netlink.Message{}, errors.New("invalid root-derived nft table name")
	}
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_TABLE_NAME, Data: append([]byte(name), 0)}})
	if err != nil {
		return netlink.Message{}, err
	}
	return netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETTABLE), Flags: netlink.Request}, Data: append([]byte{managedNFTFamily, 0, 0, 0}, attrs...)}, nil
}

func managedNFTTableHandle(messages []netlink.Message, name string) (uint64, error) {
	if !validManagedNFTName(name) || len(messages) != 1 {
		return 0, errors.New("unexpected nft table reply count or name")
	}
	m := messages[0]
	if m.Header.Type != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWTABLE) || len(m.Data) < 4 || len(m.Data) > 4096 || m.Data[0] != managedNFTFamily || m.Data[1] != 0 || m.Header.Flags&netlink.Multi != 0 {
		return 0, errors.New("invalid nft table reply")
	}
	if err := validateNFTAttributeFraming(m.Data[4:]); err != nil {
		return 0, err
	}
	attrs, err := netlink.UnmarshalAttributes(m.Data[4:])
	if err != nil {
		return 0, err
	}
	var handle uint64
	seen := make(map[uint16]bool)
	gotName := false
	for _, a := range attrs {
		kind := a.Type & 0x3fff
		if seen[kind] {
			return 0, errors.New("duplicate nft table attribute")
		}
		seen[kind] = true
		switch kind {
		case unix.NFTA_TABLE_NAME:
			if string(a.Data) != name+"\x00" {
				return 0, errors.New("nft table name changed")
			}
			gotName = true
		case nftTableHandle:
			if len(a.Data) != 8 {
				return 0, errors.New("invalid nft table handle")
			}
			handle = binary.BigEndian.Uint64(a.Data)
		case unix.NFTA_TABLE_FLAGS, unix.NFTA_TABLE_USE, nftTableOwner:
			if len(a.Data) != 4 {
				return 0, errors.New("invalid nft table scalar")
			}
		case nftTablePad:
			if len(a.Data) != 0 {
				return 0, errors.New("invalid nft table padding")
			}
		case nftTableUserdata:
			// Kernel-owned response, bounded by the complete reply size above.
		default:
			return 0, errors.New("unsupported nft table attribute")
		}
	}
	if !gotName || handle == 0 {
		return 0, errors.New("missing nft table identity")
	}
	return handle, nil
}

func managedNFTDeleteBatch(handle uint64) ([]netlink.Message, error) {
	if handle == 0 {
		return nil, errors.New("refusing unbound nft deletion")
	}
	value := make([]byte, 8)
	binary.BigEndian.PutUint64(value, handle)
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: nftTableHandle | unix.NLA_F_NET_BYTEORDER, Data: value}})
	if err != nil {
		return nil, err
	}
	return []netlink.Message{
		{Header: netlink.Header{Type: unix.NFNL_MSG_BATCH_BEGIN, Flags: netlink.Request}, Data: []byte{0, 0, 0, unix.NFNL_SUBSYS_NFTABLES}},
		{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_DELTABLE), Flags: netlink.Request | netlink.Acknowledge}, Data: append([]byte{managedNFTFamily, 0, 0, 0}, attrs...)},
		{Header: netlink.Header{Type: unix.NFNL_MSG_BATCH_END, Flags: netlink.Request}, Data: []byte{0, 0, 0, unix.NFNL_SUBSYS_NFTABLES}},
	}, nil
}

func lookupManagedNFT(ctx context.Context, hostFD int, host networkObject, name string) (uint64, error) {
	request, err := managedNFTGetMessage(name)
	if err != nil {
		return 0, err
	}
	messages, err := managedNFTExchange(ctx, hostFD, host, []netlink.Message{request}, 0)
	if err != nil {
		return 0, err
	}
	return managedNFTTableHandle(messages, name)
}

func deleteManagedNFT(ctx context.Context, hostFD int, host networkObject, name string, expected uint64) error {
	if expected == 0 {
		return errors.New("missing expected nft handle")
	}
	actual, err := lookupManagedNFT(ctx, hostFD, host, name)
	if err != nil || actual != expected {
		return errors.Join(errors.New("nft table identity changed; quarantining"), err)
	}
	batch, err := managedNFTDeleteBatch(expected)
	if err != nil {
		return err
	}
	replies, err := managedNFTExchange(ctx, hostFD, host, batch, 1)
	if err != nil {
		return err
	}
	if len(replies) != 1 || replies[0].Header.Type != netlink.Error || len(replies[0].Data) < 4 || binary.NativeEndian.Uint32(replies[0].Data[:4]) != 0 {
		return errors.New("missing successful nft deletion ACK")
	}
	return nil
}
