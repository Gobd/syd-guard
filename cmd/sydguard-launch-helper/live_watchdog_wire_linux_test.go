//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/managedlive"
	"golang.org/x/sys/unix"
)

type liveWatchTestResult struct {
	event watchdogEvent
	err   error
}
type liveWatchHarness struct {
	parent, child, pidRead, pidWrite int
	nonce                            string
	client                           *liveWatchClient
	done                             chan liveWatchTestResult
	cleaned                          chan struct{}
}

func newLiveWatchHarness(t *testing.T, duration time.Duration) *liveWatchHarness {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := make([]int, 2)
	if err := unix.Pipe2(p, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	h := &liveWatchHarness{parent: pair[0], child: pair[1], pidRead: p[0], pidWrite: p[1], nonce: strings.Repeat("a", 64), done: make(chan liveWatchTestResult, 1), cleaned: make(chan struct{}, 1)}
	h.client, err = newLiveWatchClient(h.parent, h.nonce)
	if err != nil {
		t.Fatal(err)
	}
	ops := defaultLiveWatchOps()
	ops.startup = uint64(duration)
	ops.update = uint64(duration)
	ops.partial = uint64(duration)
	go func() {
		event, err := serveLiveWatchdog(h.pidRead, h.child, h.nonce, ops, func() error { h.cleaned <- struct{}{}; return nil })
		h.done <- liveWatchTestResult{event, err}
	}()
	t.Cleanup(func() {
		_ = unix.Close(h.parent)
		_ = unix.Close(h.pidWrite)
		select {
		case <-h.done:
		case <-time.After(2 * time.Second):
			t.Error("watchdog goroutine did not exit")
		}
		_ = unix.Close(h.child)
		_ = unix.Close(h.pidRead)
	})
	return h
}
func (h *liveWatchHarness) result(t *testing.T, fail bool) liveWatchTestResult {
	t.Helper()
	select {
	case r := <-h.done:
		if (r.err != nil) != fail {
			t.Fatalf("watchdog error=%v want failure=%v", r.err, fail)
		}
		select {
		case <-h.cleaned:
		default:
			t.Fatal("whole-session cleanup not invoked")
		}
		h.done <- r
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("watchdog stalled")
		return liveWatchTestResult{}
	}
}
func watchNow(t *testing.T) uint64 {
	t.Helper()
	n, err := monotonicNanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	return n
}
func frameFor(t *testing.T, h *liveWatchHarness, op, kind byte, seq uint64, id string, accepted uint64) liveWatchFrame {
	t.Helper()
	f := liveWatchFrame{op: op, kind: kind, nonce: h.client.nonce, sequence: seq, accepted: accepted}
	for i := range f.request {
		f.request[i] = id[0]
	}
	return f
}
func sendFrame(t *testing.T, fd int, f liveWatchFrame) {
	t.Helper()
	b := f.bytes()
	n, err := unix.Write(fd, b[:])
	if err != nil || n != len(b) {
		t.Fatalf("write frame: %d %v", n, err)
	}
}
func exchangeWatch(t *testing.T, h *liveWatchHarness, f liveWatchFrame, ack byte) error {
	t.Helper()
	return h.client.exchange(f, ack, watchNow(t)+uint64(2*time.Second))
}
func initialWatch(t *testing.T, h *liveWatchHarness) liveWatchFrame {
	t.Helper()
	f := frameFor(t, h, liveWatchArm, liveWatchStartup, 1, "a", watchNow(t))
	if err := exchangeWatch(t, h, f, liveWatchArmACK); err != nil {
		t.Fatal(err)
	}
	return f
}
func completeWatch(t *testing.T, h *liveWatchHarness, f liveWatchFrame) {
	t.Helper()
	f.op = liveWatchComplete
	if err := exchangeWatch(t, h, f, liveWatchCompleteACK); err != nil {
		t.Fatal(err)
	}
}
func TestLiveWatchWireARMCompleteAndStop(t *testing.T) {
	h := newLiveWatchHarness(t, 2*time.Second)
	start := initialWatch(t, h)
	completeWatch(t, h, start)
	accepted := watchNow(t)
	f, err := h.client.arm(strings.Repeat("b", 64), 2, false, accepted)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.client.complete(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if err = h.client.stop(watchNow(t) + uint64(time.Second)); err != nil {
		t.Fatal(err)
	}
	h.result(t, false)
}
func TestLiveWatchWireDeadlineUsesOriginalAcceptance(t *testing.T) {
	h := newLiveWatchHarness(t, 350*time.Millisecond)
	accepted := watchNow(t)
	time.Sleep(150 * time.Millisecond)
	f := frameFor(t, h, liveWatchArm, liveWatchStartup, 1, "a", accepted)
	if err := exchangeWatch(t, h, f, liveWatchArmACK); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	h.result(t, true)
	elapsed := time.Since(started)
	if elapsed > 300*time.Millisecond {
		t.Fatalf("deadline restarted after ARM: %s", elapsed)
	}
}
func TestLiveWatchWireProtocolFailuresFailStop(t *testing.T) {
	for _, caseName := range []string{"overlap", "stale", "wrong_accepted", "duplicate", "wrong_nonce", "unknown", "partial", "ancillary", "lost_peer", "parent_death", "expired_arm"} {
		t.Run(caseName, func(t *testing.T) {
			h := newLiveWatchHarness(t, 150*time.Millisecond)
			switch caseName {
			case "partial":
				if _, err := unix.Write(h.parent, []byte{'W'}); err != nil {
					t.Fatal(err)
				}
			case "ancillary":
				f := frameFor(t, h, liveWatchArm, liveWatchStartup, 1, "a", watchNow(t))
				b := f.bytes()
				file, err := os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if _, err := unix.SendmsgN(h.parent, b[:], unix.UnixRights(int(file.Fd())), nil, 0); err != nil {
					t.Fatal(err)
				}
			case "lost_peer":
				if err := unix.Shutdown(h.parent, unix.SHUT_RDWR); err != nil {
					t.Fatal(err)
				}
			case "parent_death":
				if _, err := unix.Write(h.pidWrite, []byte{1}); err != nil {
					t.Fatal(err)
				}
			case "wrong_nonce":
				f := frameFor(t, h, liveWatchArm, liveWatchStartup, 1, "a", watchNow(t))
				f.nonce[0] ^= 1
				sendFrame(t, h.parent, f)
			case "unknown":
				f := frameFor(t, h, 99, liveWatchStartup, 1, "a", watchNow(t))
				sendFrame(t, h.parent, f)
			case "expired_arm":
				f := frameFor(t, h, liveWatchArm, liveWatchStartup, 1, "a", watchNow(t)-uint64(200*time.Millisecond))
				sendFrame(t, h.parent, f)
			case "overlap":
				_ = initialWatch(t, h)
				sendFrame(t, h.parent, frameFor(t, h, liveWatchArm, liveWatchUpdate, 2, "b", watchNow(t)))
			case "stale":
				f := initialWatch(t, h)
				f.op = liveWatchComplete
				f.sequence = 2
				sendFrame(t, h.parent, f)
			case "wrong_accepted":
				f := initialWatch(t, h)
				f.op = liveWatchComplete
				f.accepted++
				sendFrame(t, h.parent, f)
			case "duplicate":
				f := initialWatch(t, h)
				completeWatch(t, h, f)
				next := frameFor(t, h, liveWatchArm, liveWatchUpdate, 2, "a", watchNow(t))
				sendFrame(t, h.parent, next)
			}
			result := h.result(t, caseName != "parent_death")
			if caseName == "parent_death" && result.event.pidfdRevents == 0 {
				t.Fatal("pidfd event missing")
			}
		})
	}
}
func TestLiveWatchWireExactLimit(t *testing.T) {
	h := newLiveWatchHarness(t, 2*time.Second)
	f := initialWatch(t, h)
	completeWatch(t, h, f)
	for i := 2; i <= managedlive.MaxAcceptedOperations; i++ {
		var request [32]byte
		request[0] = byte(i >> 8)
		request[1] = byte(i)
		f = liveWatchFrame{op: liveWatchArm, kind: liveWatchUpdate, nonce: h.client.nonce, request: request, sequence: uint64(i), accepted: watchNow(t)}
		if err := exchangeWatch(t, h, f, liveWatchArmACK); err != nil {
			t.Fatalf("arm %d: %v", i, err)
		}
		completeWatch(t, h, f)
	}
	f = frameFor(t, h, liveWatchArm, liveWatchUpdate, managedlive.MaxAcceptedOperations+1, "z", watchNow(t))
	sendFrame(t, h.parent, f)
	r := h.result(t, true)
	if !strings.Contains(r.err.Error(), "invalid, stale or overlapping") {
		t.Fatal(r.err)
	}
}
func TestLiveWatchWireLostACKAndTruncatedRights(t *testing.T) {
	t.Run("lost_ack", func(t *testing.T) {
		h := newLiveWatchHarness(t, 120*time.Millisecond)
		f := frameFor(t, h, liveWatchArm, liveWatchStartup, 1, "a", watchNow(t))
		sendFrame(t, h.parent, f) // The parent never reads the ARM ACK or completes.
		h.result(t, true)
	})
	t.Run("truncated_rights_closed", func(t *testing.T) {
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(pair[0])
		defer unix.Close(pair[1])
		file, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		before, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		fds := make([]int, 100)
		for i := range fds {
			fds[i] = int(file.Fd())
		}
		if _, err := unix.SendmsgN(pair[0], []byte{1}, unix.UnixRights(fds...), nil, 0); err != nil {
			t.Fatal(err)
		}
		var b [1]byte
		if _, err := watchRecv(pair[1], b[:]); err == nil {
			t.Fatal("truncated rights accepted")
		}
		after, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		if len(before) != len(after) {
			t.Fatalf("received descriptors leaked: %d -> %d", len(before), len(after))
		}
	})
}

func TestLiveWatchWireCleanupFailurePropagates(t *testing.T) {
	p, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])
	fd := make([]int, 2)
	if err = unix.Pipe2(fd, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd[0])
	defer unix.Close(fd[1])
	nonce := strings.Repeat("a", 64)
	n, _ := liveWatchNonce(nonce)
	f := liveWatchFrame{op: liveWatchStop, nonce: n}
	sendFrame(t, p[0], f)
	sentinel := errors.New("cleanup quarantine")
	_, err = serveLiveWatchdog(fd[0], p[1], nonce, defaultLiveWatchOps(), func() error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatal(fmt.Errorf("cleanup error lost: %w", err))
	}
}
