//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/mdlayher/netlink"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNFTReplyMustBindKernelSenderAndExactHeader(t *testing.T) {
	m := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Pid: 123, Seq: 7}}
	if err := validateNFTReplyOrigin(0, m, 123, 7); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct{ sender, pid, seq uint32 }{{1, 123, 7}, {0, 0, 7}, {0, 124, 7}, {0, 123, 8}} {
		copy := m
		copy.Header.Pid = bad.pid
		copy.Header.Seq = bad.seq
		if validateNFTReplyOrigin(bad.sender, copy, 123, 7) == nil {
			t.Fatal("accepted unbound reply", bad)
		}
	}
	m.Header.Flags = unix.NLM_F_MULTI
	if validateNFTReplyOrigin(0, m, 123, 7) == nil {
		t.Fatal("accepted multipart")
	}
}

func TestNFTRejectsZeroLengthWireAttributes(t *testing.T) {
	for _, kind := range []uint16{8, unix.NFTA_TABLE_NAME, nftTableHandle} {
		b := make([]byte, 4)
		binary.NativeEndian.PutUint16(b[2:], kind)
		if validateNFTAttributeFraming(b) == nil {
			t.Fatal("accepted zero length", kind)
		}
	}
	for _, b := range [][]byte{{1}, {3, 0, 1, 0}, {8, 0, 1, 0}} {
		if validateNFTAttributeFraming(b) == nil {
			t.Fatal("accepted malformed framing", b)
		}
	}
	if err := validateNFTAttributeFraming([]byte{4, 0, 5, 0}); err != nil {
		t.Fatal(err)
	}
}

func TestNFTCanceledBeforeNamespaceAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fd, _, err := openManagedNFTSocket(ctx, -1, networkObject{})
	if err != context.Canceled || fd != -1 {
		t.Fatalf("canceled operation touched namespace: %d %v", fd, err)
	}
}

func TestNFTPollingCancellationIsBounded(t *testing.T) {
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sockets[0])
	defer unix.Close(sockets[1])
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- waitNamespaceChannel(ctx, sockets[0], unix.POLLIN) }()
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt bounded poll")
	}
}

func nftAckForTest(request netlink.Message, pid, seq uint32, code int32) syscall.NetlinkMessage {
	b := make([]byte, 4+unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(b[:4], uint32(code))
	binary.NativeEndian.PutUint32(b[4:8], uint32(unix.NLMSG_HDRLEN+len(request.Data)))
	binary.NativeEndian.PutUint16(b[8:10], uint16(request.Header.Type))
	binary.NativeEndian.PutUint16(b[10:12], uint16(request.Header.Flags))
	binary.NativeEndian.PutUint32(b[12:16], seq)
	binary.NativeEndian.PutUint32(b[16:20], pid)
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_ERROR, Pid: pid, Seq: seq}, Data: b}
}

func TestNFTTracksEveryBatchACK(t *testing.T) {
	batch := []netlink.Message{{Header: netlink.Header{Type: unix.NFNL_MSG_BATCH_BEGIN, Flags: netlink.Request}}, {Header: netlink.Header{Type: 100, Flags: netlink.Request | netlink.Acknowledge}}, {Header: netlink.Header{Type: 101, Flags: netlink.Request | netlink.Acknowledge}}, {Header: netlink.Header{Type: unix.NFNL_MSG_BATCH_END, Flags: netlink.Request}}}
	tracker, err := newNFTReplyTracker(batch, 123, 1)
	if err != nil {
		t.Fatal(err)
	}
	a := nftAckForTest(batch[1], 123, 2, 0)
	b := nftAckForTest(batch[2], 123, 3, 0)
	if err := tracker.add(0, a); err != nil || len(tracker.expected) != 1 {
		t.Fatalf("first ACK: %v", err)
	}
	if err := tracker.add(0, a); err == nil {
		t.Fatal("accepted duplicate")
	}
	if err := tracker.add(0, b); err != nil || len(tracker.expected) != 0 {
		t.Fatalf("second ACK: %v", err)
	}
	if err := tracker.add(0, b); err == nil {
		t.Fatal("accepted extra ACK")
	}
	for _, mutate := range []func(*syscall.NetlinkMessage){func(m *syscall.NetlinkMessage) { m.Header.Pid++ }, func(m *syscall.NetlinkMessage) { m.Header.Seq++ }, func(m *syscall.NetlinkMessage) { m.Data[8]++ }, func(m *syscall.NetlinkMessage) { m.Data[16]++ }, func(m *syscall.NetlinkMessage) { m.Data = m.Data[:4] }, func(m *syscall.NetlinkMessage) { m.Header.Type = unix.NLMSG_DONE }} {
		tracker, _ := newNFTReplyTracker(batch, 123, 1)
		bad := nftAckForTest(batch[1], 123, 2, 0)
		mutate(&bad)
		if tracker.add(0, bad) == nil {
			t.Fatal("accepted malformed ACK")
		}
	}
	tracker, _ = newNFTReplyTracker(batch, 123, 1)
	if err := tracker.add(1, a); err == nil {
		t.Fatal("accepted userspace sender")
	}
	tracker, _ = newNFTReplyTracker(batch, 123, 1)
	if err := tracker.add(0, nftAckForTest(batch[1], 123, 2, -int32(unix.EEXIST))); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("collision: %v", err)
	}
}

type mockNFTWire struct {
	sent             []byte
	packets          [][]byte
	sender           uint32
	sendErr, recvErr error
	extraPending     bool
}

func (w *mockNFTWire) Pending() (bool, error) { return w.extraPending, nil }
func (w *mockNFTWire) Send(b []byte) error    { w.sent = append(w.sent, b...); return w.sendErr }
func (w *mockNFTWire) Receive(_ context.Context, b []byte) (int, uint32, error) {
	if len(w.packets) == 0 {
		if w.recvErr != nil {
			return 0, 0, w.recvErr
		}
		return 0, 0, context.DeadlineExceeded
	}
	p := w.packets[0]
	w.packets = w.packets[1:]
	copy(b, p)
	return len(p), w.sender, nil
}
func ackPacket(t *testing.T, m syscall.NetlinkMessage) []byte {
	t.Helper()
	b, err := (netlink.Message{Header: netlink.Header{Length: uint32(unix.NLMSG_HDRLEN + len(m.Data)), Type: netlink.HeaderType(m.Header.Type), PID: m.Header.Pid, Sequence: m.Header.Seq}, Data: m.Data}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestNFTWireCompleteACKsAndUnknownOutcomes(t *testing.T) {
	batch := []netlink.Message{{Header: netlink.Header{Type: unix.NFNL_MSG_BATCH_BEGIN, Flags: netlink.Request}, Data: []byte{0, 0, 0, 10}}, {Header: netlink.Header{Type: 100, Flags: netlink.Request | netlink.Acknowledge}}, {Header: netlink.Header{Type: 101, Flags: netlink.Request | netlink.Acknowledge}}, {Header: netlink.Header{Type: unix.NFNL_MSG_BATCH_END, Flags: netlink.Request}, Data: []byte{0, 0, 0, 10}}}
	a := ackPacket(t, nftAckForTest(batch[1], 123, 2, 0))
	b := ackPacket(t, nftAckForTest(batch[2], 123, 3, 0))
	for _, test := range []struct {
		name    string
		packets [][]byte
		sender  uint32
		sendErr error
		wantErr bool
	}{{"complete", [][]byte{a, b}, 0, nil, false}, {"coalesced", [][]byte{append(append([]byte(nil), a...), b...)}, 0, nil, false}, {"missing", [][]byte{a}, 0, nil, true}, {"duplicate", [][]byte{append(append([]byte(nil), a...), a...)}, 0, nil, true}, {"extra", [][]byte{append(append(append([]byte(nil), a...), b...), b...)}, 0, nil, true}, {"malformed", [][]byte{{1, 2, 3}}, 0, nil, true}, {"sender", [][]byte{a}, 1, nil, true}, {"send", nil, 0, syscall.EIO, true}, {"collision", [][]byte{ackPacket(t, nftAckForTest(batch[1], 123, 2, -int32(unix.EEXIST)))}, 0, nil, true}} {
		t.Run(test.name, func(t *testing.T) {
			w := &mockNFTWire{packets: test.packets, sender: test.sender, sendErr: test.sendErr}
			replies, err := exchangeNFTWire(context.Background(), w, 123, batch, 1)
			if (err != nil) != test.wantErr {
				t.Fatalf("replies=%v err=%v", replies, err)
			}
			if test.wantErr && !errors.Is(err, nftOutcomeUnknown) {
				t.Fatalf("missing quarantine error: %v", err)
			}
			if len(w.sent) == 0 {
				t.Fatal("request not sent")
			}
			ms, err := syscall.ParseNetlinkMessage(w.sent)
			if err != nil || len(ms) != len(batch) {
				t.Fatalf("bad sent packet: %v", err)
			}
			for i, m := range ms {
				if m.Header.Pid != 123 || m.Header.Seq != uint32(i+1) {
					t.Fatalf("request identity %d: %+v", i, m.Header)
				}
			}
		})
	}
}

func TestNFTWireRejectsQueuedExtraPacket(t *testing.T) {
	batch := []netlink.Message{{Header: netlink.Header{Type: 100, Flags: netlink.Request | netlink.Acknowledge}}}
	w := &mockNFTWire{packets: [][]byte{ackPacket(t, nftAckForTest(batch[0], 123, 1, 0))}, extraPending: true}
	if _, err := exchangeNFTWire(context.Background(), w, 123, batch, 0); !errors.Is(err, nftOutcomeUnknown) {
		t.Fatalf("extra packet not quarantined: %v", err)
	}
}

func TestNFTWireACKEmbeddedHeaderMatchesNormalizedRequest(t *testing.T) {
	request := netlink.Message{
		Header: netlink.Header{Length: 999, Type: 100, Flags: netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Excl, Sequence: 999, PID: 999},
		Data:   []byte{1, 2, 3, 4},
	}
	for _, test := range []struct {
		name    string
		mutate  func(*syscall.NetlinkMessage)
		wantErr bool
	}{
		{"header-only-success", func(*syscall.NetlinkMessage) {}, false},
		{"length", func(m *syscall.NetlinkMessage) { m.Data[4] ^= 1 }, true},
		{"flags", func(m *syscall.NetlinkMessage) { m.Data[10] ^= 1 }, true},
		{"type", func(m *syscall.NetlinkMessage) { m.Data[8] ^= 1 }, true},
		{"sequence", func(m *syscall.NetlinkMessage) { m.Data[12] ^= 1 }, true},
		{"pid", func(m *syscall.NetlinkMessage) { m.Data[16] ^= 1 }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ack := nftAckForTest(request, 123, 1, 0)
			test.mutate(&ack)
			wire := &mockNFTWire{packets: [][]byte{ackPacket(t, ack)}}
			_, err := exchangeNFTWire(context.Background(), wire, 123, []netlink.Message{request}, 0)
			if test.wantErr && !errors.Is(err, nftOutcomeUnknown) {
				t.Fatalf("corrupt header did not quarantine: %v", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("header-only successful ACK: %v", err)
			}
			sent, err := syscall.ParseNetlinkMessage(wire.sent)
			if err != nil || len(sent) != 1 || sent[0].Header.Len != uint32(unix.NLMSG_HDRLEN+len(request.Data)) || sent[0].Header.Flags != uint16(request.Header.Flags) || sent[0].Header.Seq != 1 || sent[0].Header.Pid != 123 {
				t.Fatalf("request was not normalized: %v %v", sent, err)
			}
		})
	}
}
