//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/managedlive"
	"github.com/Gobd/syd-guard/internal/syd"
	"golang.org/x/sys/unix"
)

type coordinatorFixture struct {
	c       *liveCoordinator
	ledger  *syd.BankLedger
	intent  []byte
	rev     string
	events  []string
	fail    string
	stopped int
	ready   managedlive.Ready
}

func newCoordinatorFixture(t *testing.T) *coordinatorFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "sgcoord-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	work, tmp := filepath.Join(root, "project"), filepath.Join(root, "tmp")
	for _, d := range []string{work, tmp} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	b := managedlive.Binding{Session: strings.Repeat("a", 64), Project: strings.Repeat("b", 64), Profile: "build", Generation: 1}
	ledger, _, err := syd.NewBankLedger(b.BankBinding(), liveEngineDigest, work, tmp, filepath.Join(root, "s"), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	intent := []byte(`{"version":1,"name":"build","files":[],"network":[]}`)
	snapshot, err := config.ParseManagedProfileSnapshot("build", intent)
	if err != nil {
		t.Fatal(err)
	}
	f := &coordinatorFixture{ledger: ledger, intent: intent, rev: snapshot.Revision()}
	f.c = &liveCoordinator{binding: b, initialRevision: f.rev, initialBank: ledger.InitialReceipt()}
	fail := func(phase string) error {
		f.events = append(f.events, phase)
		if f.fail == phase {
			return errors.New("injected " + phase)
		}
		return nil
	}
	f.c.ops = liveCoordinatorOps{
		authenticate: func(_ context.Context, credential string) error {
			if credential != strings.Repeat("c", 64) {
				return errors.New("bad credential")
			}
			return fail("auth")
		},
		arm: func(_ string, seq uint64, startup bool, accepted uint64) (liveWatchFrame, error) {
			if err := fail("arm"); err != nil {
				return liveWatchFrame{}, err
			}
			return liveWatchFrame{sequence: seq, accepted: accepted, kind: map[bool]byte{true: liveWatchStartup, false: liveWatchUpdate}[startup], op: liveWatchArm}, nil
		},
		complete: func(context.Context, liveWatchFrame) error { return fail("complete") },
		prepare: func(_ context.Context, revision string, prev syd.BankReceipt) (syd.BankBatch, error) {
			if err := fail("prepare"); err != nil {
				return syd.BankBatch{}, err
			}
			if revision != f.rev {
				return syd.BankBatch{}, errors.New("exact revision missing")
			}
			return ledger.Prepare(prev, f.intent)
		},
		load: func(_ context.Context, data []byte) error {
			if len(data) == 0 {
				t.Fatal("empty batch")
			}
			return fail("load")
		},
		finish: func(r syd.BankReceipt, ack bool) error {
			if err := fail("finish"); err != nil {
				return err
			}
			return ledger.Finish(r, ack)
		},
		quarantine: func() { f.events = append(f.events, "quarantine"); ledger.Stop() },
		stop:       func() error { f.events = append(f.events, "stop"); f.stopped++; return nil },
		release:    func() error { return fail("release") },
	}
	return f
}
func (f *coordinatorFixture) start(t *testing.T) {
	t.Helper()
	r, err := f.c.start(context.Background(), strings.Repeat("1", 64), strings.Repeat("2", 64), f.rev)
	if err != nil {
		t.Fatal(err)
	}
	f.ready = r
}
func (f *coordinatorFixture) release(t *testing.T) {
	t.Helper()
	err := f.c.release(context.Background(), managedlive.Release{Version: managedlive.Version, Kind: "release", Credential: strings.Repeat("c", 64), Ready: f.ready.Receipt})
	if err != nil {
		t.Fatal(err)
	}
}
func (f *coordinatorFixture) update() managedlive.ApplySaved {
	return managedlive.ApplySaved{Version: managedlive.Version, Kind: "apply_saved", Credential: strings.Repeat("c", 64), Binding: f.c.binding, RequestID: strings.Repeat("d", 64), Sequence: 2, Revision: f.rev, Predecessor: f.ready.Receipt.Bank}
}
func TestLiveCoordinatorStartupReleaseAndUpdateOrder(t *testing.T) {
	f := newCoordinatorFixture(t)
	f.start(t)
	if !reflect.DeepEqual(f.events, []string{"arm", "prepare", "load", "finish"}) {
		t.Fatal(f.events)
	}
	f.release(t)
	if !reflect.DeepEqual(f.events, []string{"arm", "prepare", "load", "finish", "auth", "release", "complete"}) {
		t.Fatal(f.events)
	}
	f.events = nil
	applied, err := f.c.apply(context.Background(), f.update())
	if err != nil {
		t.Fatal(err)
	}
	if applied.Receipt.Bank.Sequence != 2 || applied.Receipt.Bank.Revision != f.rev {
		t.Fatal(applied)
	}
	if !reflect.DeepEqual(f.events, []string{"auth", "arm", "prepare", "load", "finish", "complete"}) {
		t.Fatal(f.events)
	}
	status, err := f.c.status()
	if err != nil || status.Receipt != applied.Receipt {
		t.Fatal(status, err)
	}
	f.events = nil
	if _, err := f.c.apply(context.Background(), f.update()); err == nil {
		t.Fatal("duplicate accepted")
	}
	if f.stopped != 0 || !reflect.DeepEqual(f.events, []string{"auth"}) {
		t.Fatal(f.events)
	}
	if err := f.c.release(context.Background(), managedlive.Release{Version: managedlive.Version, Kind: "release", Credential: strings.Repeat("c", 64), Ready: f.ready.Receipt}); err == nil {
		t.Fatal("duplicate release")
	}
}
func TestLiveCoordinatorPreARMFailureDoesNotAccept(t *testing.T) {
	f := newCoordinatorFixture(t)
	f.start(t)
	f.release(t)
	f.events = nil
	beforePhase, before, deadline := f.c.state.Snapshot()
	f.fail = "arm"
	if _, err := f.c.apply(context.Background(), f.update()); err == nil {
		t.Fatal("ARM failure accepted")
	}
	phase, after, newDeadline := f.c.state.Snapshot()
	if phase != beforePhase || before != after || deadline != newDeadline || f.stopped != 0 || !reflect.DeepEqual(f.events, []string{"auth", "arm"}) {
		t.Fatal(f.events, phase, after)
	}
}
func TestLiveCoordinatorPostARMFailuresAreUnknown(t *testing.T) {
	for _, phase := range []string{"prepare", "load", "finish", "complete"} {
		t.Run(phase, func(t *testing.T) {
			f := newCoordinatorFixture(t)
			f.start(t)
			f.release(t)
			f.events = nil
			f.fail = phase
			_, err := f.c.apply(context.Background(), f.update())
			if !errors.Is(err, errLiveUnknown) || f.stopped != 1 {
				t.Fatalf("%s: %v %v", phase, err, f.events)
			}
			if _, err = f.c.status(); !errors.Is(err, errLiveUnknown) {
				t.Fatal("old receipt presented", err)
			}
			if _, err = f.ledger.Prepare(f.c.initialBank, f.intent); err == nil {
				t.Fatal("failed ledger reused")
			}
		})
	}
}
func TestLiveCoordinatorStartupReleaseFailureStops(t *testing.T) {
	for _, phase := range []string{"prepare", "load", "finish", "release", "complete"} {
		t.Run(phase, func(t *testing.T) {
			f := newCoordinatorFixture(t)
			if phase == "release" || phase == "complete" {
				f.start(t)
			}
			f.fail = phase
			var err error
			if phase == "release" || phase == "complete" {
				err = f.c.release(context.Background(), managedlive.Release{Version: managedlive.Version, Kind: "release", Credential: strings.Repeat("c", 64), Ready: f.ready.Receipt})
			} else {
				_, err = f.c.start(context.Background(), strings.Repeat("1", 64), strings.Repeat("2", 64), f.rev)
			}
			if !errors.Is(err, errLiveUnknown) || f.stopped != 1 {
				t.Fatal(err, f.events)
			}
		})
	}
}
func TestLiveCoordinatorPreARMStallDoesNotPublish(t *testing.T) {
	f := newCoordinatorFixture(t)
	f.start(t)
	f.release(t)
	_, before, deadline := f.c.state.Snapshot()
	entered := make(chan struct{})
	unblock := make(chan struct{})
	f.c.ops.arm = func(string, uint64, bool, uint64) (liveWatchFrame, error) {
		close(entered)
		<-unblock
		return liveWatchFrame{}, errors.New("lost ARM")
	}
	done := make(chan error, 1)
	go func() { _, err := f.c.apply(context.Background(), f.update()); done <- err }()
	<-entered
	if _, err := f.c.status(); err == nil {
		t.Fatal("busy coordinator returned status")
	}
	if _, err := f.c.apply(context.Background(), f.update()); err == nil {
		t.Fatal("busy update accepted")
	}
	close(unblock)
	if err := <-done; err == nil {
		t.Fatal("ARM failure accepted")
	}
	_, after, afterDeadline := f.c.state.Snapshot()
	if before != after || deadline != afterDeadline || f.stopped != 0 {
		t.Fatal("pre-ARM state changed")
	}
}
func TestLiveCoordinatorExpiredStartupCannotReportReady(t *testing.T) {
	f := newCoordinatorFixture(t)
	state, err := managedlive.NewState(f.c.binding, strings.Repeat("1", 64), strings.Repeat("2", 64), f.rev, time.Now().Add(-managedlive.StartupTimeout-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	f.c.state = state
	if _, err := f.c.status(); !errors.Is(err, errLiveUnknown) || f.stopped != 1 {
		t.Fatal("expired startup remained visible", err)
	}
}

func TestLiveCoordinatorTerminalContextStops(t *testing.T) {
	for _, boundary := range []string{"startup_finish", "release_complete", "update_complete"} {
		for _, mode := range []string{"canceled", "earlier_deadline"} {
			t.Run(boundary+"/"+mode, func(t *testing.T) {
				f := newCoordinatorFixture(t)
				if boundary != "startup_finish" {
					f.start(t)
				}
				if boundary == "update_complete" {
					f.release(t)
				}
				var ctx context.Context
				var cancel context.CancelFunc
				if mode == "canceled" {
					ctx, cancel = context.WithCancel(context.Background())
				} else {
					ctx, cancel = context.WithTimeout(context.Background(), 75*time.Millisecond)
				}
				defer cancel()
				expire := func() {
					if mode == "canceled" {
						cancel()
					} else {
						<-ctx.Done()
					}
				}
				if boundary == "startup_finish" {
					original := f.c.ops.finish
					f.c.ops.finish = func(r syd.BankReceipt, ack bool) error {
						if err := original(r, ack); err != nil {
							return err
						}
						expire()
						return nil
					}
					ready, err := f.c.start(ctx, strings.Repeat("1", 64), strings.Repeat("2", 64), f.rev)
					if !errors.Is(err, errLiveUnknown) || !errors.Is(err, ctx.Err()) || ready != (managedlive.Ready{}) || f.c.ready != (managedlive.Ready{}) {
						t.Fatalf("startup published or lost context cause: %+v %v", ready, err)
					}
				} else {
					original := f.c.ops.complete
					f.c.ops.complete = func(op context.Context, frame liveWatchFrame) error {
						if err := original(op, frame); err != nil {
							return err
						}
						expire()
						return nil
					}
					if boundary == "release_complete" {
						err := f.c.release(ctx, managedlive.Release{Version: managedlive.Version, Kind: "release", Credential: strings.Repeat("c", 64), Ready: f.ready.Receipt})
						if !errors.Is(err, errLiveUnknown) || !errors.Is(err, ctx.Err()) {
							t.Fatalf("release succeeded or lost context cause: %v", err)
						}
					} else {
						applied, err := f.c.apply(ctx, f.update())
						if !errors.Is(err, errLiveUnknown) || !errors.Is(err, ctx.Err()) || applied != (managedlive.Applied{}) {
							t.Fatalf("update published or lost context cause: %+v %v", applied, err)
						}
					}
				}
				phase, _, _ := f.c.state.Snapshot()
				if phase != "stopped" || f.stopped != 1 {
					t.Fatalf("state not stopped: %s stop=%d", phase, f.stopped)
				}
				if _, err := f.c.status(); !errors.Is(err, errLiveUnknown) {
					t.Fatalf("status remained available: %v", err)
				}
				if _, err := f.ledger.Prepare(f.c.initialBank, f.intent); err == nil {
					t.Fatal("ledger not quarantined")
				}
			})
		}
	}
}

func TestLiveWatchCompleteHonorsCallerContext(t *testing.T) {
	for _, mode := range []string{"cancel", "earlier_deadline"} {
		t.Run(mode, func(t *testing.T) {
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pair[0])
			defer unix.Close(pair[1])
			client, err := newLiveWatchClient(pair[0], strings.Repeat("a", 64))
			if err != nil {
				t.Fatal(err)
			}
			accepted, err := monotonicNanoseconds()
			if err != nil {
				t.Fatal(err)
			}
			frame := liveWatchFrame{op: liveWatchArm, kind: liveWatchUpdate, nonce: client.nonce, sequence: 2, accepted: accepted}
			var ctx context.Context
			var cancel context.CancelFunc
			if mode == "cancel" {
				ctx, cancel = context.WithCancel(context.Background())
			} else {
				ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
			}
			defer cancel()
			started := time.Now()
			done := make(chan error, 1)
			go func() { done <- client.complete(ctx, frame) }()
			fds := []unix.PollFd{{Fd: int32(pair[1]), Events: unix.POLLIN}}
			if n, err := unix.Poll(fds, 1000); err != nil || n != 1 {
				cancel()
				<-done
				t.Fatalf("COMPLETE frame missing: %d %v", n, err)
			}
			var encoded [liveWatchFrameSize]byte
			count := 0
			for count < len(encoded) {
				n, err := unix.Read(pair[1], encoded[count:])
				if errors.Is(err, unix.EAGAIN) {
					if n, e := unix.Poll(fds, 1000); e != nil || n != 1 {
						cancel()
						<-done
						t.Fatalf("partial frame stalled: %d %v", n, e)
					}
					continue
				}
				if err != nil || n == 0 {
					cancel()
					<-done
					t.Fatalf("frame read: %d %v", n, err)
				}
				count += n
			}
			got, err := decodeLiveWatchFrame(encoded[:])
			if err != nil {
				cancel()
				<-done
				t.Fatal(err)
			}
			expected := frame
			expected.op = liveWatchComplete
			if got != expected {
				cancel()
				<-done
				t.Fatal("COMPLETE changed original wire binding or timestamp")
			}
			if mode == "cancel" {
				cancel()
			}
			err = <-done
			want := context.Canceled
			if mode == "earlier_deadline" {
				want = context.DeadlineExceeded
			}
			if !errors.Is(err, want) || time.Since(started) > time.Second {
				t.Fatalf("COMPLETE ignored context: %v", err)
			}
		})
	}
}

func TestLiveCoordinatorCompleteACKDeadline(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	nonce := strings.Repeat("a", 64)
	client, err := newLiveWatchClient(pair[0], nonce)
	if err != nil {
		t.Fatal(err)
	}
	now, err := monotonicNanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	frame := liveWatchFrame{op: liveWatchArm, kind: liveWatchUpdate, nonce: client.nonce, sequence: 2, accepted: now - uint64(managedlive.UpdateTimeout) + uint64(100*time.Millisecond)}
	start := time.Now()
	if err := client.complete(context.Background(), frame); err == nil || time.Since(start) > time.Second {
		t.Fatal("blocked COMPLETE ACK not bounded", err)
	}
}
