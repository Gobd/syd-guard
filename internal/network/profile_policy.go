package network

import (
	"context"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Gobd/syd-guard/internal/config"
)

// ManagedBinding is supplied by the trusted controller, not by the workload.
// The identifiers are opaque and must identify one registered project and start.
type ManagedBinding struct {
	SessionID         string
	ProjectID         string
	ProfileName       string
	SessionGeneration string
	StartIdentity     string
}

// AppliedNetworkRevision identifies only the network policy installed in this
// process. It is not evidence of persistence, filesystem application, or I/O.
// Epoch prevents stale revisions from succeeding after an A-B-A replacement.
type AppliedNetworkRevision struct {
	Binding  ManagedBinding
	Revision string
	Epoch    uint64
}

type managedProfile struct {
	applied AppliedNetworkRevision
	targets map[Target]bool
}

type policyEpoch struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func validOpaque(s string) bool {
	return s != "" && len(s) <= 512 && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}

func profileTargets(binding ManagedBinding, snapshot config.ProfileSnapshot) (string, map[Target]bool, error) {
	if !validOpaque(binding.SessionID) || !validOpaque(binding.ProjectID) || !validOpaque(binding.SessionGeneration) || !validOpaque(binding.StartIdentity) || config.ProfileName(binding.ProfileName) != nil {
		return "", nil, fmt.Errorf("invalid managed binding")
	}
	// Reparse exact bytes so even a zero or mismatched snapshot cannot acquire authority.
	validated, err := config.ParseManagedProfileSnapshot(binding.ProfileName, snapshot.Bytes())
	if err != nil || validated.Revision() != snapshot.Revision() {
		return "", nil, fmt.Errorf("invalid managed profile snapshot")
	}
	rules := validated.Profile().Network
	if len(rules) > 4096 {
		return "", nil, fmt.Errorf("network target limit exceeded")
	}
	targets := make(map[Target]bool, len(rules))
	for _, rule := range rules {
		target, err := Canonical(rule.Host, rule.Port)
		if err != nil || target.Host != rule.Host || rule.Transport != "tcp" || ReservedServiceHost(target.Host) || targets[target] {
			return "", nil, fmt.Errorf("invalid or duplicate managed network target")
		}
		targets[target] = true
	}
	return validated.Revision(), targets, nil
}

// BindManagedProfile installs the initial exact network snapshot once per live
// session. The controller must authenticate the binding and snapshot itself.
func (p *Policy) BindManagedProfile(ctx context.Context, binding ManagedBinding, snapshot config.ProfileSnapshot) (AppliedNetworkRevision, error) {
	revision, targets, err := profileTargets(binding, snapshot)
	if err != nil {
		return AppliedNetworkRevision{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return AppliedNetworkRevision{}, err
	}
	if p.ended[binding.SessionID] || p.managed[binding.SessionID] != nil {
		return AppliedNetworkRevision{}, fmt.Errorf("session ended or already bound")
	}
	p.cutoverLocked(binding.SessionID)
	applied := AppliedNetworkRevision{Binding: binding, Revision: revision, Epoch: 1}
	p.managed[binding.SessionID] = &managedProfile{applied: applied, targets: targets}
	return applied, nil
}

// ReplaceManagedProfile atomically replaces the complete profile-owned target
// set. The expected receipt is session-specific and rejects ABA revisions.
// Connections already past final admission may continue; future dials and
// in-flight pre-admission dials are revoked at cutover.
func (p *Policy) ReplaceManagedProfile(ctx context.Context, expected AppliedNetworkRevision, snapshot config.ProfileSnapshot) (AppliedNetworkRevision, error) {
	revision, targets, err := profileTargets(expected.Binding, snapshot)
	if err != nil {
		return AppliedNetworkRevision{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return AppliedNetworkRevision{}, err
	}
	current := p.managed[expected.Binding.SessionID]
	if p.ended[expected.Binding.SessionID] || current == nil || current.applied != expected || expected.Epoch == ^uint64(0) {
		return AppliedNetworkRevision{}, fmt.Errorf("stale or mismatched managed network revision")
	}
	p.cutoverLocked(expected.Binding.SessionID)
	applied := AppliedNetworkRevision{Binding: expected.Binding, Revision: revision, Epoch: expected.Epoch + 1}
	p.managed[expected.Binding.SessionID] = &managedProfile{applied: applied, targets: targets}
	return applied, nil
}

func (p *Policy) allowedLocked(session string, target Target) bool {
	if p.ended[session] {
		return false
	}
	if managed := p.managed[session]; managed != nil {
		return p.trusted[session][target] || managed.targets[target]
	}
	return !p.denied[session][target] && (p.trusted[session][target] || p.durable[target] || p.run[session][target])
}

func (p *Policy) cutoverLocked(session string) {
	if old := p.epochs[session]; old != nil {
		old.cancel()
		delete(p.epochs, session)
	}
}

// beginDial and admitDial linearize admission with profile cutovers. Neither
// DNS nor socket operations run under the policy lock.
func (p *Policy) beginDial(ctx context.Context, session, name string, target Target) (context.Context, context.CancelFunc, *policyEpoch, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.checkLocked(session, name, target) {
		return nil, nil, nil, false
	}
	epoch := p.epochs[session]
	if epoch == nil {
		epoch = &policyEpoch{}
		epoch.ctx, epoch.cancel = context.WithCancel(context.Background())
		p.epochs[session] = epoch
	}
	dialCtx, cancel := context.WithCancel(epoch.ctx)
	stop := context.AfterFunc(ctx, cancel)
	if ctx.Err() != nil {
		cancel()
	}
	return dialCtx, func() { stop(); cancel() }, epoch, true
}

func (p *Policy) admitDial(session string, target Target, epoch *policyEpoch) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.epochs[session] == epoch && p.allowedLocked(session, target)
}
