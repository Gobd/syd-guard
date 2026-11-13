//go:build linux

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/Gobd/syd-guard/internal/managedlive"
)

// liveStartupArm is a ROOT-only, single-use handoff. It is not serializable and
// is never sent to an operator, child, supervisor or workload.
type liveStartupArm struct {
	mu                          sync.Mutex
	owner                       *liveWatchClient
	binding                     managedlive.Binding
	ticket, requestID, revision string
	start                       time.Time
	frame                       liveWatchFrame
	used                        bool
}

func armLiveStartup(w *liveWatchClient, b managedlive.Binding, ticket, requestID, revision string) (*liveStartupArm, error) {
	if w == nil || managedlive.ValidateStartup(b, ticket, requestID, revision) != nil || hex.EncodeToString(w.nonce[:]) != b.Session {
		return nil, errors.New("invalid startup ARM binding")
	}
	start := time.Now()
	mono, err := monotonicNanoseconds()
	if err != nil {
		return nil, err
	}
	frame, err := w.arm(requestID, 1, true, mono)
	if err != nil {
		return nil, err
	}
	return &liveStartupArm{owner: w, binding: b, ticket: ticket, requestID: requestID, revision: revision, start: start, frame: frame}, nil
}

// startAdopted is called only after ROOT has spawned and pinned the engine and
// taken over its socket. Those steps consume the already-running budget.
func (c *liveCoordinator) startAdopted(ctx context.Context, token *liveStartupArm) (managedlive.Ready, error) {
	if !c.mu.TryLock() {
		return managedlive.Ready{}, errors.New("live coordinator busy")
	}
	defer c.mu.Unlock()
	if token == nil || c.broken || c.state != nil {
		return managedlive.Ready{}, errors.New("invalid startup adoption")
	}
	token.mu.Lock()
	defer token.mu.Unlock()
	if token.used || token.owner == nil || token.owner != c.watch || token.binding != c.binding || token.revision != c.initialRevision || token.frame.op != liveWatchArm || token.frame.kind != liveWatchStartup || token.frame.sequence != 1 || token.frame.accepted == 0 || token.frame.nonce != token.owner.nonce || hex.EncodeToString(token.frame.request[:]) != token.requestID || token.start.IsZero() {
		return managedlive.Ready{}, c.fail(errors.New("startup adoption binding mismatch"))
	}
	token.used = true
	if ctx == nil || ctx.Err() != nil || !time.Now().Before(token.start.Add(managedlive.StartupTimeout)) {
		return managedlive.Ready{}, c.fail(errors.New("startup adoption deadline"))
	}
	return c.startBankLocked(ctx, token.ticket, token.requestID, token.revision, token.start, token.frame)
}
