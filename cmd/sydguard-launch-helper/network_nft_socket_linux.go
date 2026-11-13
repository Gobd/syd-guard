//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Avoid the dependency's NetNS==0 sentinel and callback-error propagation bug.
// Own a positive duplicate, verify it, enter only on a disposable locked thread,
// and retain the created socket (whose namespace is fixed at creation).
func openManagedNFTSocket(ctx context.Context, borrowed int, object networkObject) (int, uint32, error) {
	if err := ctx.Err(); err != nil {
		return -1, 0, err
	}
	fd, err := unix.FcntlInt(uintptr(borrowed), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return -1, 0, err
	}
	if err = verifyNetworkNamespaceFD(fd, object); err != nil {
		unix.Close(fd)
		return -1, 0, err
	}
	type result struct {
		fd  int
		pid uint32
		err error
	}
	done := make(chan result)
	go func() {
		runtime.LockOSThread() // never unlock: Go discards the altered thread
		defer unix.Close(fd)
		r := result{fd: -1}
		r.err = unix.Setns(fd, unix.CLONE_NEWNET)
		if r.err == nil {
			r.fd, r.err = unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
		}
		if r.err == nil {
			r.err = unix.Bind(r.fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		}
		if r.err == nil {
			var addr unix.Sockaddr
			addr, r.err = unix.Getsockname(r.fd)
			if r.err == nil {
				a, ok := addr.(*unix.SockaddrNetlink)
				if !ok || a.Pid == 0 {
					r.err = errors.New("invalid nft socket port identity")
				} else {
					r.pid = a.Pid
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
			return -1, 0, err
		}
		return r.fd, r.pid, r.err
	case <-ctx.Done():
		return -1, 0, ctx.Err()
	}
}

func validateNFTReplyOrigin(sender uint32, m syscall.NetlinkMessage, pid, seq uint32) error {
	if sender != 0 || pid == 0 || m.Header.Pid != pid || m.Header.Seq != seq || m.Header.Flags&unix.NLM_F_MULTI != 0 {
		return errors.New("unbound nft kernel reply")
	}
	return nil
}

// nftOutcomeUnknown means the request may have committed and its resources
// must remain quarantined; it is never a reason to retry a create or delete.
var nftOutcomeUnknown = errors.New("nft transaction outcome unknown; quarantine")

// nftReplyTracker enforces one response per requested ACK, or one GET reply.
// It also checks the embedded request header in every kernel ACK.
type nftReplyTracker struct {
	requests []netlink.Message
	pid      uint32
	expected map[uint32]bool
	replies  []netlink.Message
	get      bool
}

func newNFTReplyTracker(messages []netlink.Message, pid uint32, index int) (*nftReplyTracker, error) {
	if len(messages) == 0 || len(messages) > 128 || pid == 0 || index < 0 || index >= len(messages) {
		return nil, errors.New("invalid nft transaction")
	}
	// Use the same normalized headers for serialization and ACK validation;
	// ignore caller-supplied length, sequence and PID in both places.
	requests := append([]netlink.Message(nil), messages...)
	for i := range requests {
		if len(requests[i].Data) > 65536-unix.NLMSG_HDRLEN {
			return nil, errors.New("nft message exceeds bound")
		}
		requests[i].Header.Length = uint32(unix.NLMSG_HDRLEN + len(requests[i].Data))
		requests[i].Header.Sequence = uint32(i + 1)
		requests[i].Header.PID = pid
	}
	t := &nftReplyTracker{requests: requests, pid: pid, expected: make(map[uint32]bool)}
	if len(messages) == 1 && messages[0].Header.Flags&netlink.Acknowledge == 0 {
		t.get = true
		t.expected[1] = true
	} else {
		for i, m := range messages {
			if m.Header.Flags&netlink.Acknowledge != 0 {
				t.expected[uint32(i+1)] = true
			}
		}
		if len(t.expected) == 0 || !t.expected[uint32(index+1)] {
			return nil, errors.New("missing expected nft ACK")
		}
	}
	return t, nil
}

func (t *nftReplyTracker) add(sender uint32, m syscall.NetlinkMessage) error {
	seq := m.Header.Seq
	if !t.expected[seq] {
		return errors.New("unexpected or duplicate nft reply")
	}
	if err := validateNFTReplyOrigin(sender, m, t.pid, seq); err != nil {
		return err
	}
	if m.Header.Type == unix.NLMSG_ERROR {
		if len(m.Data) < 4+unix.NLMSG_HDRLEN {
			return errors.New("short nft error ACK")
		}
		r := t.requests[seq-1]
		orig := m.Data[4 : 4+unix.NLMSG_HDRLEN]
		if binary.NativeEndian.Uint32(orig[0:4]) != r.Header.Length ||
			binary.NativeEndian.Uint16(orig[4:6]) != uint16(r.Header.Type) ||
			binary.NativeEndian.Uint16(orig[6:8]) != uint16(r.Header.Flags) ||
			binary.NativeEndian.Uint32(orig[8:12]) != r.Header.Sequence ||
			binary.NativeEndian.Uint32(orig[12:16]) != r.Header.PID {
			return errors.New("nft ACK request identity mismatch")
		}
		code := int32(binary.NativeEndian.Uint32(m.Data[:4]))
		if code < 0 {
			return syscall.Errno(-int64(code))
		}
		if code != 0 || t.get {
			return errors.New("invalid nft ACK")
		}
	} else if !t.get {
		return errors.New("nft ACK expected")
	}
	delete(t.expected, seq)
	t.replies = append(t.replies, netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(m.Header.Type), Flags: netlink.HeaderFlags(m.Header.Flags), Sequence: seq, PID: m.Header.Pid}, Data: append([]byte(nil), m.Data...)})
	return nil
}

func managedNFTExchange(ctx context.Context, hostFD int, host networkObject, messages []netlink.Message, index int) ([]netlink.Message, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	fd, pid, err := openManagedNFTSocket(ctx, hostFD, host)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	return managedNFTExchangeSocket(ctx, fd, pid, messages, index)
}

type nftWire interface {
	Send([]byte) error
	Receive(context.Context, []byte) (int, uint32, error)
	Pending() (bool, error)
}

type nativeNFTWire struct{ fd int }

func (w nativeNFTWire) Send(b []byte) error {
	return unix.Sendto(w.fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}
func (w nativeNFTWire) Pending() (bool, error) {
	var b [1]byte
	_, _, _, _, err := unix.Recvmsg(w.fd, b[:], nil, unix.MSG_DONTWAIT|unix.MSG_PEEK)
	if errors.Is(err, unix.EAGAIN) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
func (w nativeNFTWire) Receive(ctx context.Context, buf []byte) (int, uint32, error) {
	for {
		if err := waitNamespaceChannel(ctx, w.fd, unix.POLLIN); err != nil {
			return 0, 0, err
		}
		n, _, flags, from, err := unix.Recvmsg(w.fd, buf, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, 0, err
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 || flags&unix.MSG_TRUNC != 0 || n < unix.NLMSG_HDRLEN {
			return 0, 0, errors.New("invalid nft sender/packet")
		}
		return n, sender.Pid, nil
	}
}

func managedNFTExchangeSocket(ctx context.Context, fd int, pid uint32, messages []netlink.Message, index int) ([]netlink.Message, error) {
	return exchangeNFTWire(ctx, nativeNFTWire{fd: fd}, pid, messages, index)
}

func exchangeNFTWire(ctx context.Context, wire nftWire, pid uint32, messages []netlink.Message, index int) ([]netlink.Message, error) {
	tracker, err := newNFTReplyTracker(messages, pid, index)
	if err != nil {
		return nil, err
	}
	var packet []byte
	for _, m := range tracker.requests {
		b, err := m.MarshalBinary()
		if err != nil {
			return nil, err
		}
		packet = append(packet, b...)
	}
	if len(packet) > 65536 {
		return nil, errors.New("nft transaction exceeds bound")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := wire.Send(packet); err != nil {
		return nil, errors.Join(nftOutcomeUnknown, err)
	}
	buf := make([]byte, 65536)
	for len(tracker.expected) != 0 {
		n, sender, err := wire.Receive(ctx, buf)
		if err != nil {
			return nil, errors.Join(nftOutcomeUnknown, err)
		}
		if sender != 0 || n < unix.NLMSG_HDRLEN || n > len(buf) {
			return nil, errors.Join(nftOutcomeUnknown, errors.New("invalid nft sender/packet"))
		}

		// ParseNetlinkMessage accepts partial trailing bytes, so validate all frames first.
		for off := 0; off < n; {
			if n-off < unix.NLMSG_HDRLEN {
				return nil, errors.Join(nftOutcomeUnknown, errors.New("short nft frame"))
			}
			length := int(binary.NativeEndian.Uint32(buf[off : off+4]))
			if length < unix.NLMSG_HDRLEN || length > n-off || (length+3)&^3 > n-off {
				return nil, errors.Join(nftOutcomeUnknown, errors.New("invalid nft frame length"))
			}
			off += (length + 3) &^ 3
		}
		parsed, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil || len(parsed) == 0 {
			return nil, errors.Join(nftOutcomeUnknown, errors.New("unexpected nft framing"))
		}
		for _, m := range parsed {
			if err := tracker.add(sender, m); err != nil {
				return nil, errors.Join(nftOutcomeUnknown, fmt.Errorf("nft response: %w", err))
			}
		}
	}
	pending, err := wire.Pending()
	if err != nil {
		return nil, errors.Join(nftOutcomeUnknown, err)
	}
	if pending {
		return nil, errors.Join(nftOutcomeUnknown, errors.New("unexpected extra nft packet"))
	}
	return tracker.replies, nil
}

// UnmarshalAttributes skips zero-length attributes. Validate the raw framing
// first so malformed/duplicate/unknown headers cannot disappear before checks.
func validateNFTAttributeFraming(b []byte) error {
	for len(b) != 0 {
		if len(b) < 4 {
			return errors.New("short nft attribute header")
		}
		n := int(binary.NativeEndian.Uint16(b[:2]))
		padded := (n + 3) &^ 3
		if n < 4 || n > len(b) || padded > len(b) {
			return errors.New("invalid nft attribute length")
		}
		b = b[padded:]
	}
	return nil
}
