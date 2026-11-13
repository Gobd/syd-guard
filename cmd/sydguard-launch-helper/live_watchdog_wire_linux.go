//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/Gobd/syd-guard/internal/managedlive"
	"golang.org/x/sys/unix"
)

// The fixed private stream carries no cgroup, PID, path, credential or engine
// authority. Only the already-authenticated ROOT parent owns the peer FD.
const liveWatchFrameSize = 84
const (
	liveWatchArm         byte = 1
	liveWatchArmACK      byte = 2
	liveWatchComplete    byte = 3
	liveWatchCompleteACK byte = 4
	liveWatchStop        byte = 5
	liveWatchStartup     byte = 1
	liveWatchUpdate      byte = 2
)

type liveWatchFrame struct {
	op, kind           byte
	nonce, request     [32]byte
	sequence, accepted uint64
}

func (f liveWatchFrame) bytes() [liveWatchFrameSize]byte {
	var b [liveWatchFrameSize]byte
	b[0] = 'W'
	b[1] = 1
	b[2] = f.op
	b[3] = f.kind
	copy(b[4:36], f.nonce[:])
	copy(b[36:68], f.request[:])
	binary.BigEndian.PutUint64(b[68:76], f.sequence)
	binary.BigEndian.PutUint64(b[76:84], f.accepted)
	return b
}
func decodeLiveWatchFrame(b []byte) (liveWatchFrame, error) {
	var f liveWatchFrame
	if len(b) != liveWatchFrameSize || b[0] != 'W' || b[1] != 1 {
		return f, errors.New("invalid watchdog frame")
	}
	f.op = b[2]
	f.kind = b[3]
	copy(f.nonce[:], b[4:36])
	copy(f.request[:], b[36:68])
	f.sequence = binary.BigEndian.Uint64(b[68:76])
	f.accepted = binary.BigEndian.Uint64(b[76:84])
	return f, nil
}
func liveWatchNonce(value string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != 32 || hex.EncodeToString(b) != value {
		return out, errors.New("invalid watchdog nonce")
	}
	copy(out[:], b)
	return out, nil
}
func monotonicNanoseconds() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	if ts.Sec < 0 || ts.Nsec < 0 || ts.Nsec >= 1e9 || uint64(ts.Sec) > math.MaxUint64/1_000_000_000 {
		return 0, errors.New("invalid monotonic clock")
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec), nil
}

type liveWatchOps struct {
	now                      func() (uint64, error)
	poll                     func([]unix.PollFd, int) (int, error)
	startup, update, partial uint64
}

func defaultLiveWatchOps() liveWatchOps {
	return liveWatchOps{now: monotonicNanoseconds, poll: unix.Poll, startup: uint64(managedlive.StartupTimeout), update: uint64(managedlive.UpdateTimeout), partial: uint64(managedlive.UpdateTimeout)}
}
func livePollTimeout(now, deadline uint64) int {
	if deadline == 0 {
		return -1
	}
	if now >= deadline {
		return 0
	}
	ms := (deadline - now + uint64(time.Millisecond) - 1) / uint64(time.Millisecond)
	if ms > math.MaxInt32 {
		return math.MaxInt32
	}
	return int(ms)
}
func closeWatchRights(oob []byte) {
	msgs, _ := unix.ParseSocketControlMessage(oob)
	for _, m := range msgs {
		fds, err := unix.ParseUnixRights(&m)
		if err == nil {
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
		}
	}
}
func watchRecv(fd int, b []byte) (int, error) {
	oob := make([]byte, unix.CmsgSpace(4*64))
	n, on, flags, _, err := unix.Recvmsg(fd, b, oob, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
	if on > 0 {
		closeWatchRights(oob[:on])
	}
	if on > 0 || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
		return 0, errors.New("unexpected watchdog ancillary data")
	}
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}
func watchSend(fd int, b []byte) (int, error) {
	return unix.SendmsgN(fd, b, nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
}

// waitLiveWatchdogEvent runs only after the existing peer/journal/pidfd checks.
// Any protocol/I/O/clock error is fail-stop. The caller must always invoke the
// identity-checked whole-cgroup cleanup, even when this function returns error.
func waitLiveWatchdogEvent(parentFD, socketFD int, nonce string, ops liveWatchOps) (watchdogEvent, error) {
	expected, err := liveWatchNonce(nonce)
	if err != nil {
		return watchdogEvent{}, err
	}
	if ops.now == nil || ops.poll == nil || ops.startup == 0 || ops.update == 0 || ops.partial == 0 {
		return watchdogEvent{}, errors.New("invalid watchdog timing")
	}
	//nolint:gosec // validated Linux descriptors
	fds := []unix.PollFd{{Fd: int32(parentFD), Events: unix.POLLIN}, {Fd: int32(socketFD), Events: unix.POLLIN | unix.POLLHUP}}
	var input [liveWatchFrameSize]byte
	inCount := 0
	var partialDeadline uint64
	var pending *liveWatchFrame
	var deadline uint64
	var ack [liveWatchFrameSize]byte
	ackCount := 0
	ackPending := false
	var completed uint64
	used := make(map[[32]byte]bool)
	event := func(n int) watchdogEvent {
		return watchdogEvent{at: time.Now(), count: n, pidfdRevents: fds[0].Revents, socketRevents: fds[1].Revents}
	}
	for {
		now, e := ops.now()
		if e != nil {
			return event(0), e
		}
		if deadline != 0 && now >= deadline {
			return event(0), errors.New("live watchdog operation deadline")
		}
		if partialDeadline != 0 && now >= partialDeadline {
			return event(0), errors.New("partial watchdog frame deadline")
		}
		limit := deadline
		if partialDeadline != 0 && (limit == 0 || partialDeadline < limit) {
			limit = partialDeadline
		}
		fds[0].Revents = 0
		fds[1].Revents = 0
		fds[1].Events = unix.POLLIN | unix.POLLHUP
		if ackPending {
			fds[1].Events |= unix.POLLOUT
		}
		n, e := ops.poll(fds, livePollTimeout(now, limit))
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if e != nil {
			return event(n), e
		}
		now, e = ops.now()
		if e != nil {
			return event(n), e
		}
		if deadline != 0 && now >= deadline {
			return event(n), errors.New("live watchdog operation deadline")
		}
		if partialDeadline != 0 && now >= partialDeadline {
			return event(n), errors.New("partial watchdog frame deadline")
		}
		if fds[0].Revents != 0 {
			return event(n), nil
		}
		if fds[1].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return event(n), errors.New("watchdog peer lost")
		}
		if ackPending && fds[1].Revents&unix.POLLIN != 0 {
			return event(n), errors.New("watchdog request before acknowledgement")
		}
		if ackPending && fds[1].Revents&unix.POLLOUT != 0 {
			count, writeErr := watchSend(socketFD, ack[ackCount:])
			if errors.Is(writeErr, unix.EAGAIN) || errors.Is(writeErr, unix.EINTR) {
				continue
			}
			if writeErr != nil || count <= 0 {
				return event(n), errors.New("watchdog acknowledgement lost")
			}
			ackCount += count
			afterWrite, clockErr := ops.now()
			if clockErr != nil {
				return event(n), clockErr
			}
			if deadline != 0 && afterWrite >= deadline {
				return event(n), errors.New("late watchdog acknowledgement")
			}
			if ackCount == len(ack) {
				if ack[2] == liveWatchCompleteACK {
					completed = pending.sequence
					pending = nil
					deadline = 0
				}
				ackPending = false
				ackCount = 0
			}
			continue
		}
		if fds[1].Revents&unix.POLLIN == 0 {
			continue
		}
		count, readErr := watchRecv(socketFD, input[inCount:])
		if errors.Is(readErr, unix.EAGAIN) || errors.Is(readErr, unix.EINTR) {
			continue
		}
		if readErr != nil {
			return event(n), readErr
		}
		if inCount == 0 {
			if now > math.MaxUint64-ops.partial {
				return event(n), errors.New("watchdog clock overflow")
			}
			partialDeadline = now + ops.partial
		}
		inCount += count
		if inCount < len(input) {
			continue
		}
		inCount = 0
		partialDeadline = 0
		f, parseErr := decodeLiveWatchFrame(input[:])
		if parseErr != nil || f.nonce != expected {
			return event(n), errors.New("invalid watchdog frame binding")
		}
		if f.op == liveWatchStop {
			if f.kind != 0 || f.sequence != 0 || f.accepted != 0 || f.request != ([32]byte{}) {
				return event(n), errors.New("invalid watchdog stop")
			}
			return event(n), nil
		}
		switch f.op {
		case liveWatchArm:
			if pending != nil || completed >= managedlive.MaxAcceptedOperations || f.sequence != completed+1 || used[f.request] || f.accepted == 0 || f.accepted > now {
				return event(n), errors.New("invalid, stale or overlapping watchdog arm")
			}
			duration := ops.update
			if f.sequence == 1 {
				if f.kind != liveWatchStartup {
					return event(n), errors.New("missing startup arm")
				}
				duration = ops.startup
			} else if f.kind != liveWatchUpdate {
				return event(n), errors.New("invalid update arm")
			}
			if f.accepted > math.MaxUint64-duration || now >= f.accepted+duration {
				return event(n), errors.New("expired watchdog arm")
			}
			deadline = f.accepted + duration
			pending = &f
			used[f.request] = true
			f.op = liveWatchArmACK
			ack = f.bytes()
			ackPending = true
		case liveWatchComplete:
			if pending == nil || f.kind != pending.kind || f.request != pending.request || f.sequence != pending.sequence || f.accepted != pending.accepted {
				return event(n), errors.New("unknown watchdog completion")
			}
			f.op = liveWatchCompleteACK
			ack = f.bytes()
			ackPending = true
		default:
			return event(n), errors.New("unknown watchdog operation")
		}
	}
}

// serveLiveWatchdog guarantees the existing identity-bound cleanup runs after
// every event, including malformed frames, lost ACK, timeout and parent death.
func serveLiveWatchdog(parentFD, socketFD int, nonce string, ops liveWatchOps, cleanup func() error) (watchdogEvent, error) {
	event, err := waitLiveWatchdogEvent(parentFD, socketFD, nonce, ops)
	if cleanup == nil {
		return event, errors.Join(err, errors.New("missing watchdog cleanup"))
	}
	return event, errors.Join(err, cleanup())
}

// liveWatchClient is private to the ROOT parent. accepted is obtained from
// CLOCK_MONOTONIC at acceptance, before ARM, and is never restarted by I/O.
type liveWatchClient struct {
	fd    int
	nonce [32]byte
}

func newLiveWatchClient(fd int, nonce string) (*liveWatchClient, error) {
	n, err := liveWatchNonce(nonce)
	if err != nil {
		return nil, err
	}
	return &liveWatchClient{fd: fd, nonce: n}, nil
}
func (c *liveWatchClient) exchange(f liveWatchFrame, ackOp byte, deadline uint64) error {
	return c.exchangeContext(context.Background(), f, ackOp, deadline)
}

// exchangeContext keeps the watchdog's original monotonic deadline and frame
// unchanged. Bounded polling also observes an earlier caller cancellation.
func (c *liveWatchClient) exchangeContext(ctx context.Context, f liveWatchFrame, ackOp byte, deadline uint64) error {
	if ctx == nil {
		return errors.New("watchdog context required")
	}
	data := f.bytes()
	var reply [liveWatchFrameSize]byte
	sent, read := 0, 0
	for {
		if err := watchExchangeContextErr(ctx); err != nil {
			return err
		}
		now, err := monotonicNanoseconds()
		if err != nil {
			return err
		}
		if now >= deadline {
			return errors.New("watchdog request deadline")
		}
		if sent == len(data) && ackOp == 0 {
			return nil
		}
		events := int16(unix.POLLIN)
		if sent < len(data) {
			events = unix.POLLOUT
		}
		//nolint:gosec // validated Linux descriptor
		fds := []unix.PollFd{{Fd: int32(c.fd), Events: events | unix.POLLHUP}}
		timeout := livePollTimeout(now, deadline)
		if callerDeadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(callerDeadline)
			if remaining <= 0 {
				return context.DeadlineExceeded
			}
			ms := remaining / time.Millisecond
			if remaining%time.Millisecond != 0 {
				ms++
			}
			if ms > math.MaxInt32 {
				ms = math.MaxInt32
			}
			if ms < time.Duration(timeout) || timeout < 0 {
				timeout = int(ms)
			}
		}
		// A context can be canceled without a deadline. Poll briefly rather
		// than spawning a goroutine that could outlive or close this FD.
		if ctx.Done() != nil && (timeout < 0 || timeout > 20) {
			timeout = 20
		}
		_, err = unix.Poll(fds, timeout)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if err := watchExchangeContextErr(ctx); err != nil {
			return err
		}
		if fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return errors.New("watchdog peer lost")
		}
		if fds[0].Revents&events == 0 {
			continue
		}
		if sent < len(data) {
			n, e := watchSend(c.fd, data[sent:])
			if errors.Is(e, unix.EAGAIN) || errors.Is(e, unix.EINTR) {
				continue
			}
			if e != nil || n <= 0 {
				return errors.New("watchdog request write failed")
			}
			sent += n
			continue
		}
		n, e := watchRecv(c.fd, reply[read:])
		if errors.Is(e, unix.EAGAIN) || errors.Is(e, unix.EINTR) {
			continue
		}
		if e != nil {
			return e
		}
		read += n
		if read < len(reply) {
			continue
		}
		f.op = ackOp
		expected := f.bytes()
		if !bytes.Equal(reply[:], expected[:]) {
			return errors.New("watchdog acknowledgement mismatch")
		}
		now, err = monotonicNanoseconds()
		if err != nil {
			return err
		}
		if now >= deadline {
			return errors.New("late watchdog acknowledgement")
		}
		return watchExchangeContextErr(ctx)
	}
}

func watchExchangeContextErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *liveWatchClient) arm(request string, sequence uint64, startup bool, accepted uint64) (liveWatchFrame, error) {
	var f liveWatchFrame
	raw, err := hex.DecodeString(request)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != request || sequence == 0 || sequence > managedlive.MaxAcceptedOperations {
		return f, errors.New("invalid watchdog operation")
	}
	copy(f.request[:], raw)
	f.nonce = c.nonce
	f.sequence = sequence
	f.accepted = accepted
	f.op = liveWatchArm
	f.kind = liveWatchUpdate
	duration := uint64(managedlive.UpdateTimeout)
	if startup {
		if sequence != 1 {
			return f, errors.New("invalid startup operation")
		}
		f.kind = liveWatchStartup
		duration = uint64(managedlive.StartupTimeout)
	} else if sequence == 1 {
		return f, errors.New("missing startup operation")
	}
	if accepted == 0 || accepted > math.MaxUint64-duration {
		return f, errors.New("invalid accepted time")
	}
	if err := c.exchange(f, liveWatchArmACK, accepted+duration); err != nil {
		return liveWatchFrame{}, fmt.Errorf("watchdog arm: %w", err)
	}
	return f, nil
}
func (c *liveWatchClient) complete(ctx context.Context, f liveWatchFrame) error {
	duration := uint64(managedlive.UpdateTimeout)
	if f.kind == liveWatchStartup {
		duration = uint64(managedlive.StartupTimeout)
	}
	if f.op != liveWatchArm || f.nonce != c.nonce || f.accepted == 0 || f.accepted > math.MaxUint64-duration {
		return errors.New("invalid watchdog completion")
	}
	f.op = liveWatchComplete
	return c.exchangeContext(ctx, f, liveWatchCompleteACK, f.accepted+duration)
}

// A sent STOP is not a cleanup receipt. The parent must still obtain the
// watchdog's cleanup acknowledgement or retain/quarantine the slot.
func (c *liveWatchClient) stop(deadline uint64) error {
	return c.exchange(liveWatchFrame{op: liveWatchStop, nonce: c.nonce}, 0, deadline)
}
