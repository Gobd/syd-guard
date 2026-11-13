//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Gobd/syd-guard/internal/managedlive"
	"github.com/Gobd/syd-guard/internal/syd"
	"golang.org/x/sys/unix"
)

var errLiveUnknown = errors.New("live outcome unknown; whole-session fail-stop required")

// These unexported operations are assembled solely from ROOT-owned resources.
// They are not a remotely selectable helper API; tests inject ordinary fakes.
type liveCoordinatorOps struct {
	authenticate func(context.Context, string) error
	arm          func(string, uint64, bool, uint64) (liveWatchFrame, error)
	complete     func(context.Context, liveWatchFrame) error
	prepare      func(context.Context, string, syd.BankReceipt) (syd.BankBatch, error)
	load         func(context.Context, []byte) error
	finish       func(syd.BankReceipt, bool) error
	quarantine   func()
	stop         func() error
	release      func() error
}
type liveCoordinator struct {
	mu              sync.Mutex
	binding         managedlive.Binding
	initialRevision string
	initialBank     syd.BankReceipt
	ops             liveCoordinatorOps
	state           *managedlive.State
	ready           managedlive.Ready
	startup         liveWatchFrame
	watch           *liveWatchClient
	broken          bool
}

// newLiveCoordinator requires validated held authority, a private engine
// endpoint and the ROOT watchdog. stop/release are fixed ROOT-owned handoffs,
// not controller callbacks. Executable peer pinning and private mount layout
// remain mandatory future startup gates; this constructor does not activate it.
func newLiveCoordinator(a *liveAuthority, w *liveWatchClient, e *liveEngineEndpoint, b managedlive.Binding, stop, release func() error) (*liveCoordinator, error) {
	if os.Geteuid() != 0 || a == nil || a.engine == nil || a.ledger == nil || a.store == nil || a.original == nil || w == nil || e == nil || stop == nil || release == nil {
		return nil, errors.New("missing ROOT coordinator authority")
	}
	initial := a.ledger.InitialReceipt()
	if initial.Binding != b.BankBinding() || initial.Binding.Session != fmt.Sprintf("%x", w.nonce) || a.projectID != b.Project || a.name != b.Profile {
		return nil, errors.New("coordinator binding mismatch")
	}
	// The same retained FD was validated and hashed by the authority constructor;
	// revalidate it at this ownership handoff before the ledger can be used.
	if err := checkHeldCoordinatorEngine(a.engine); err != nil {
		return nil, err
	}
	return &liveCoordinator{binding: b, initialRevision: a.original.Revision, initialBank: initial, watch: w, ops: liveCoordinatorOps{authenticate: a.store.AuthenticateContext, arm: w.arm, complete: w.complete, prepare: a.prepareSaved, load: e.load, finish: a.ledger.Finish, quarantine: a.ledger.Stop, stop: stop, release: release}}, nil
}

func checkHeldCoordinatorEngine(file *os.File) error {
	var identity unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &identity); err != nil {
		return err
	}
	return checkLiveEngine(file, identity, 0)
}

func (c *liveCoordinator) fail(err error) error {
	c.broken = true
	if c.state != nil {
		c.state.Stop()
	}
	c.ops.quarantine()
	return errors.Join(errLiveUnknown, err, c.ops.stop())
}
func liveBudget(ctx context.Context, start time.Time, duration time.Duration) (context.Context, context.CancelFunc, error) {
	if ctx == nil || start.IsZero() || ctx.Err() != nil {
		return nil, nil, errors.New("invalid operation context")
	}
	deadline := start.Add(duration)
	if !time.Now().Before(deadline) {
		return nil, nil, context.DeadlineExceeded
	}
	child, cancel := context.WithDeadline(ctx, deadline)
	return child, cancel, nil
}
func checkLiveBudget(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// start arms before publishing a state or reading saved bytes. The initial ARM
// remains outstanding after Ready until the exact gated release is completed.
func (c *liveCoordinator) start(ctx context.Context, ticket, requestID, revision string) (managedlive.Ready, error) {
	if !c.mu.TryLock() {
		return managedlive.Ready{}, errors.New("live coordinator busy")
	}
	defer c.mu.Unlock()
	if c.broken || c.state != nil || revision != c.initialRevision || managedlive.ValidateStartup(c.binding, ticket, requestID, revision) != nil {
		return managedlive.Ready{}, errors.New("invalid live startup")
	}
	if ctx == nil || ctx.Err() != nil {
		return managedlive.Ready{}, errors.New("invalid startup context")
	}
	start := time.Now()
	mono, err := monotonicNanoseconds()
	if err != nil {
		return managedlive.Ready{}, err
	}
	frame, err := c.ops.arm(requestID, 1, true, mono)
	if err != nil {
		c.broken = true
		return managedlive.Ready{}, err
	}
	return c.startBankLocked(ctx, ticket, requestID, revision, start, frame)
}

// startBankLocked consumes an already-acknowledged startup ARM and never
// changes its acceptance timestamp or renews its watchdog budget.
func (c *liveCoordinator) startBankLocked(ctx context.Context, ticket, requestID, revision string, start time.Time, frame liveWatchFrame) (managedlive.Ready, error) {
	var err error
	c.state, err = managedlive.NewState(c.binding, ticket, requestID, revision, start)
	if err != nil {
		return managedlive.Ready{}, c.fail(err)
	}
	op, cancel, err := liveBudget(ctx, start, managedlive.StartupTimeout)
	if err != nil {
		return managedlive.Ready{}, c.fail(err)
	}
	defer cancel()
	batch, err := c.ops.prepare(op, revision, c.initialBank)
	if err != nil {
		return managedlive.Ready{}, c.fail(err)
	}
	if batch.Receipt.Binding != c.binding.BankBinding() || batch.Receipt.Sequence != 1 || batch.Receipt.Revision != revision {
		return managedlive.Ready{}, c.fail(errors.New("initial bank mismatch"))
	}
	if err = checkLiveBudget(op); err != nil {
		return managedlive.Ready{}, c.fail(err)
	}
	if err = c.ops.load(op, batch.Bytes()); err != nil {
		return managedlive.Ready{}, c.fail(err)
	}
	if err = checkLiveBudget(op); err != nil {
		return managedlive.Ready{}, c.fail(err)
	}
	if err = c.ops.finish(batch.Receipt, true); err != nil {
		return managedlive.Ready{}, c.fail(err)
	}
	if err = checkLiveBudget(op); err != nil {
		return managedlive.Ready{}, c.fail(err)
	}
	bank := managedlive.BankReceipt{Binding: c.binding, Sequence: batch.Receipt.Sequence, Revision: batch.Receipt.Revision}
	ready, err := c.state.CompleteInitial(requestID, bank, time.Now())
	if err != nil {
		return managedlive.Ready{}, c.fail(err)
	}
	c.ready = ready
	c.startup = frame
	return ready, nil
}

// release validates the entire Ready receipt before touching the fixed release
// handoff. Only a released gate plus exact watchdog completion permits running.
func (c *liveCoordinator) release(ctx context.Context, m managedlive.Release) error {
	if !c.mu.TryLock() {
		return errors.New("live coordinator busy")
	}
	defer c.mu.Unlock()
	if c.broken || c.state == nil || m.Version != managedlive.Version || m.Kind != "release" || m.Ready != c.ready.Receipt {
		return errors.New("invalid or stale release")
	}
	phase, _, _ := c.state.Snapshot()
	if phase != "ready" {
		return errors.New("invalid or stale release")
	}
	if ctx == nil {
		return errors.New("authentication context required")
	}
	_, _, deadline := c.state.Snapshot()
	op, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	authErr := c.ops.authenticate(op, m.Credential)
	if !time.Now().Before(deadline) {
		return c.fail(context.DeadlineExceeded)
	}
	if authErr != nil {
		return authErr
	}
	if err := checkLiveBudget(op); err != nil {
		return c.fail(err)
	}
	if err := c.ops.release(); err != nil {
		return c.fail(err)
	}
	if err := checkLiveBudget(op); err != nil {
		return c.fail(err)
	}
	if err := c.ops.complete(op, c.startup); err != nil {
		return c.fail(err)
	}
	if err := checkLiveBudget(op); err != nil {
		return c.fail(err)
	}
	if err := c.state.Release(c.ready.Receipt, time.Now()); err != nil {
		return c.fail(err)
	}
	return nil
}

// apply rejects unauthenticated and invalid requests without arming. State holds
// its own lock throughout exact prevalidation, ARM ACK and pending commit.
func (c *liveCoordinator) apply(ctx context.Context, m managedlive.ApplySaved) (managedlive.Applied, error) {
	if !c.mu.TryLock() {
		return managedlive.Applied{}, errors.New("live coordinator busy")
	}
	defer c.mu.Unlock()
	if c.broken || c.state == nil || ctx == nil {
		return managedlive.Applied{}, errors.New("live coordinator unavailable")
	}
	if err := c.ops.authenticate(ctx, m.Credential); err != nil {
		return managedlive.Applied{}, err
	}
	if err := ctx.Err(); err != nil {
		return managedlive.Applied{}, err
	}
	var frame liveWatchFrame
	var start time.Time
	armAttempted := false
	_, err := c.state.AcceptArmedUpdate(m, func() (time.Time, error) {
		start = time.Now()
		mono, e := monotonicNanoseconds()
		if e != nil {
			return time.Time{}, e
		}
		armAttempted = true
		frame, e = c.ops.arm(m.RequestID, m.Sequence, false, mono)
		if e != nil {
			return time.Time{}, e
		}
		return start, nil
	})
	if err != nil {
		if armAttempted {
			c.broken = true
		}
		return managedlive.Applied{}, err
	}
	op, cancel, err := liveBudget(ctx, start, managedlive.UpdateTimeout)
	if err != nil {
		return managedlive.Applied{}, c.fail(err)
	}
	defer cancel()
	batch, err := c.ops.prepare(op, m.Revision, m.Predecessor.BankReceipt())
	if err != nil {
		return managedlive.Applied{}, c.fail(err)
	}
	if batch.Receipt.Binding != c.binding.BankBinding() || batch.Receipt.Sequence != m.Sequence || batch.Receipt.Revision != m.Revision {
		return managedlive.Applied{}, c.fail(errors.New("saved bank mismatch"))
	}
	if err = checkLiveBudget(op); err != nil {
		return managedlive.Applied{}, c.fail(err)
	}
	if err = c.ops.load(op, batch.Bytes()); err != nil {
		return managedlive.Applied{}, c.fail(err)
	}
	if err = checkLiveBudget(op); err != nil {
		return managedlive.Applied{}, c.fail(err)
	}
	if err = c.ops.finish(batch.Receipt, true); err != nil {
		return managedlive.Applied{}, c.fail(err)
	}
	if err = checkLiveBudget(op); err != nil {
		return managedlive.Applied{}, c.fail(err)
	}
	if err = c.ops.complete(op, frame); err != nil {
		return managedlive.Applied{}, c.fail(err)
	}
	if err = checkLiveBudget(op); err != nil {
		return managedlive.Applied{}, c.fail(err)
	}
	bank := managedlive.BankReceipt{Binding: c.binding, Sequence: batch.Receipt.Sequence, Revision: batch.Receipt.Revision}
	applied, err := c.state.CompleteUpdate(m.RequestID, bank, true, time.Now())
	if err != nil {
		return managedlive.Applied{}, c.fail(err)
	}
	return applied, nil
}
func (c *liveCoordinator) status() (managedlive.Status, error) {
	if !c.mu.TryLock() {
		return managedlive.Status{}, errors.New("live coordinator busy")
	}
	defer c.mu.Unlock()
	if c.broken || c.state == nil {
		return managedlive.Status{}, errLiveUnknown
	}
	phase, _, deadline := c.state.Snapshot()
	if (phase == "starting" || phase == "ready") && !time.Now().Before(deadline) {
		return managedlive.Status{}, c.fail(context.DeadlineExceeded)
	}
	return c.state.Status()
}
