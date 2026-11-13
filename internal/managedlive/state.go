package managedlive

import (
	"errors"
	"sync"
	"time"
)

const StartupTimeout = 10 * time.Second
const UpdateTimeout = 5 * time.Second

// MaxAcceptedOperations includes startup. All accepted IDs are retained until
// session teardown, so duplicate and ABA protection never relies on eviction.
const MaxAcceptedOperations = 4096

// State enforces the ROOT-side receipt order. Authentication and independent
// watchdog enforcement must precede use; it performs no I/O or agent release.
type State struct {
	mu       sync.Mutex
	binding  Binding
	ticket   string
	phase    string
	current  BankReceipt
	ready    Receipt
	latest   Receipt
	pending  *pending
	used     map[string]bool
	deadline time.Time
}
type pending struct {
	id, revision string
	sequence     uint64
}

func ValidateStartup(binding Binding, ticket, initialID, revision string) error {
	if !binding.valid() || !hexID(ticket) || !hexID(initialID) || !hexID(revision) {
		return errors.New("invalid startup state")
	}
	return nil
}

func NewState(binding Binding, ticket, initialID, revision string, now time.Time) (*State, error) {
	if ValidateStartup(binding, ticket, initialID, revision) != nil || now.IsZero() {
		return nil, errors.New("invalid startup state")
	}
	return &State{binding: binding, ticket: ticket, phase: "starting", current: BankReceipt{Binding: binding}, pending: &pending{id: initialID, revision: revision, sequence: 1}, used: map[string]bool{initialID: true}, deadline: now.Add(StartupTimeout)}, nil
}

// CompleteInitial requires the exact ACKed receipt; the startup deadline stays
// armed until Release, not merely until the engine responds.
func (s *State) CompleteInitial(id string, bank BankReceipt, now time.Time) (Ready, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != "starting" || s.pending == nil || !now.Before(s.deadline) || !s.matches(id, bank) {
		s.phase = "stopped"
		return Ready{}, errors.New("initial outcome uncertain; fail-stop")
	}
	s.current = bank
	s.pending = nil
	s.phase = "ready"
	s.ready = Receipt{Version: Version, RequestID: id, Phase: "ready", EngineDigest: EngineDigest, Bank: bank}
	s.latest = s.ready
	return Ready{Version: Version, Kind: "ready", Ticket: s.ticket, Receipt: s.ready}, nil
}
func (s *State) Release(ready Receipt, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != "ready" || ready != s.ready {
		return errors.New("stale or duplicate release")
	}
	if !now.Before(s.deadline) {
		s.phase = "stopped"
		return errors.New("startup deadline; fail-stop")
	}
	s.phase = "running"
	s.deadline = time.Time{}
	return nil
}

// AcceptUpdate rejects stale/busy/duplicate requests before acceptance; after
// success any failure must stop the session. The watchdog must independently
// ARM this exact id/sequence and acknowledge before saved bytes are opened.
func (s *State) AcceptUpdate(m ApplySaved, now time.Time) (time.Time, error) {
	return s.AcceptArmedUpdate(m, func() (time.Time, error) { return now, nil })
}

// AcceptArmedUpdate holds the state lock across validation, the trusted ARM
// handshake and commit. The callback must return the original start time only
// after the watchdog acknowledges this exact request; it must not access State.
func (s *State) AcceptArmedUpdate(m ApplySaved, arm func() (time.Time, error)) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validate(&m); err != nil {
		return time.Time{}, err
	}
	if s.phase != "running" || s.pending != nil || m.Binding != s.binding || m.Predecessor != s.current || s.used[m.RequestID] || arm == nil {
		return time.Time{}, errors.New("stale, busy or duplicate update")
	}
	if len(s.used) >= MaxAcceptedOperations {
		return time.Time{}, errors.New("session accepted-operation limit reached")
	}
	now, err := arm()
	if err != nil {
		return time.Time{}, err
	}
	if now.IsZero() {
		return time.Time{}, errors.New("invalid operation start")
	}
	s.used[m.RequestID] = true
	s.pending = &pending{id: m.RequestID, revision: m.Revision, sequence: m.Sequence}
	s.deadline = now.Add(UpdateTimeout)
	return s.deadline, nil
}
func (s *State) matches(id string, b BankReceipt) bool {
	return s.pending != nil && s.pending.id == id && s.pending.sequence == b.Sequence && s.pending.revision == b.Revision && b.Binding == s.binding
}

// CompleteUpdate may publish Applied only for an exact successful engine ACK.
func (s *State) CompleteUpdate(id string, bank BankReceipt, ack bool, now time.Time) (Applied, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != "running" || !ack || !now.Before(s.deadline) || !s.matches(id, bank) {
		s.phase = "stopped"
		s.pending = nil
		return Applied{}, errors.New("update outcome uncertain; fail-stop")
	}
	s.current = bank
	s.pending = nil
	s.deadline = time.Time{}
	s.latest = Receipt{Version: Version, RequestID: id, Phase: "applied", EngineDigest: EngineDigest, Bank: bank}
	return Applied{Version: Version, Kind: "applied", Receipt: s.latest}, nil
}

// Stop quarantines the state after an accepted or otherwise uncertain outcome.
func (s *State) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.phase = "stopped"
	s.pending = nil
	s.deadline = time.Time{}
}

// Status returns only the last completed receipt, never a pending update.
func (s *State) Status() (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != "ready" && s.phase != "running" {
		return Status{}, errors.New("no current live receipt")
	}
	return Status{Version: Version, Kind: "status_result", Receipt: s.latest}, nil
}

// Snapshot is read-only: it never changes or renews an outstanding deadline.
func (s *State) Snapshot() (string, BankReceipt, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.phase, s.current, s.deadline
}
