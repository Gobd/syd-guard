//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const networkDumpLimit = 1024 * 1024

// checkNetworkCollisionInNamespace uses a verified duplicate of the pinned
// host namespace; the altered thread is discarded, never returned to Go.
func checkNetworkCollisionInNamespace(ctx context.Context, p networkPlan, fd int, object networkObject) error {
	dup, err := duplicateRouteNamespace(fd, object)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer unix.Close(dup)
		if err := unix.Setns(dup, unix.CLONE_NEWNET); err != nil {
			done <- err
			return
		}
		done <- checkNetworkCollision(ctx, p)
	}()
	select {
	case err := <-done:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// checkNetworkCollision reads the host IPv4 route and address tables through
// bounded NETLINK_ROUTE dumps. The adapter must recheck before activation and
// reject concurrent topology changes; a successful snapshot is not a lock.
func checkNetworkCollision(ctx context.Context, p networkPlan) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if !p.Host.Is4() || !p.Agent.Is4() || p.Agent != p.Host.Next() {
		return errors.New("invalid generated transit addresses")
	}
	prefix := netip.PrefixFrom(p.Host, 30).Masked()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	for _, request := range []struct {
		kind uint16
		size int
	}{{unix.RTM_GETROUTE, unix.SizeofRtMsg}, {unix.RTM_GETADDR, unix.SizeofIfAddrmsg}} {
		if err := readNetworkDump(ctx, fd, request.kind, request.size, prefix); err != nil {
			return err
		}
	}
	return nil
}

func readNetworkDump(ctx context.Context, fd int, request uint16, payloadSize int, prefix netip.Prefix) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	packet := make([]byte, unix.NLMSG_HDRLEN+payloadSize)
	binary.NativeEndian.PutUint32(packet[0:4], uint32(len(packet)))
	binary.NativeEndian.PutUint16(packet[4:6], request)
	binary.NativeEndian.PutUint16(packet[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(packet[8:12], 1)
	packet[unix.NLMSG_HDRLEN] = unix.AF_INET
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	total := 0
	buf := make([]byte, 65536)
	for {
		if err := waitNamespaceChannel(ctx, fd, unix.POLLIN); err != nil {
			return err
		}
		n, _, flags, from, err := unix.Recvmsg(fd, buf, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return err
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 || flags&unix.MSG_TRUNC != 0 || n == 0 {
			return errors.New("invalid netlink dump sender or packet")
		}
		total += n
		if total > networkDumpLimit {
			return errors.New("netlink dump exceeds bound")
		}
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil || len(messages) == 0 {
			return errors.New("invalid netlink dump")
		}
		for _, message := range messages {
			if message.Header.Seq != 1 || message.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return errors.New("interrupted or mismatched netlink dump")
			}
			switch message.Header.Type {
			case unix.NLMSG_DONE:
				if len(message.Data) != 0 && (len(message.Data) < 4 || binary.NativeEndian.Uint32(message.Data[:4]) != 0) {
					return errors.New("netlink dump completion failed")
				}
				return nil
			case unix.NLMSG_ERROR:
				return errors.New("netlink dump failed")
			case unix.RTM_NEWROUTE:
				if request != unix.RTM_GETROUTE {
					return errors.New("unexpected netlink route")
				}
			case unix.RTM_NEWADDR:
				if request != unix.RTM_GETADDR {
					return errors.New("unexpected netlink address")
				}
			default:
				return errors.New("unexpected netlink message")
			}
			overlaps, err := networkMessageOverlaps(message, prefix)
			if err != nil {
				return err
			}
			if overlaps {
				return fmt.Errorf("generated transit prefix conflicts with host network")
			}
		}
	}
}

func networkMessageOverlaps(message syscall.NetlinkMessage, prefix netip.Prefix) (bool, error) {
	var bits int
	var types []uint16
	switch message.Header.Type {
	case unix.RTM_NEWROUTE:
		if len(message.Data) < unix.SizeofRtMsg || message.Data[0] != unix.AF_INET {
			return false, errors.New("invalid IPv4 route")
		}
		bits = int(message.Data[1])
		types = []uint16{unix.RTA_DST}
		// The host's default route is intentionally superseded by a connected /30.
		if bits == 0 {
			return false, nil
		}
	case unix.RTM_NEWADDR:
		if len(message.Data) < unix.SizeofIfAddrmsg || message.Data[0] != unix.AF_INET {
			return false, errors.New("invalid IPv4 address")
		}
		bits = int(message.Data[1])
		types = []uint16{unix.IFA_ADDRESS, unix.IFA_LOCAL}
	default:
		return false, errors.New("unsupported netlink identity")
	}
	if bits > 32 {
		return false, errors.New("invalid IPv4 prefix length")
	}
	attrs, err := syscall.ParseNetlinkRouteAttr(&message)
	if err != nil {
		return false, err
	}
	seen := make(map[uint16]bool)
	found := false
	for _, attr := range attrs {
		kind := attr.Attr.Type & 0x3fff
		wanted := false
		for _, value := range types {
			if kind == value {
				wanted = true
			}
		}
		if !wanted {
			continue
		}
		if seen[kind] || len(attr.Value) != 4 {
			return false, errors.New("invalid network prefix attribute")
		}
		seen[kind], found = true, true
		address := netip.AddrFrom4([4]byte{attr.Value[0], attr.Value[1], attr.Value[2], attr.Value[3]})
		if prefix.Overlaps(netip.PrefixFrom(address, bits).Masked()) {
			return true, nil
		}
	}
	if !found {
		return false, errors.New("network prefix missing")
	}
	return false, nil
}
