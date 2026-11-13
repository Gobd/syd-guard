package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/managedlive"
	"github.com/Gobd/syd-guard/internal/session"
)

const managedLiveQueueLimit = 8

// ManagedLiveDial is supplied only by a trusted future ROOT-ready bootstrap.
// It must honor cancellation and return a fresh private connection per request.
// No browser-provided endpoint or selector is accepted.
type ManagedLiveDial = managedLiveDial

type liveOperation struct {
	revision string
	ordinal  uint64
}
type liveBinding struct {
	mu          sync.Mutex
	binding     managedlive.Binding
	credential  string
	dial        ManagedLiveDial
	predecessor managedlive.BankReceipt
	lastReceipt managedlive.Receipt
	ordinal     uint64
	exchange    func(context.Context, ManagedLiveDial, any) (any, error)
	status      session.ManagedLiveStatus
	queue       chan liveOperation
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	provider    *ManagedProfileProvider
}

// RegisterManagedRootReady is an internal integration hook, not an HTTP route.
// Its caller must have authenticated the genuine ROOT Ready response and own the
// connection factory and credential. readyReceivedAt must be the controller clock
// sampled when the authenticated Ready arrived. Never replay an old binding after
// retained records are pruned. Nothing invokes this in the default launcher.
func (s *Server) RegisterManagedRootReady(sessionID string, ready managedlive.Ready, readyReceivedAt time.Time, credential string, dial ManagedLiveDial) error {
	if readyReceivedAt.IsZero() || readyReceivedAt.After(time.Now()) {
		return errors.New("invalid ready receipt time")
	}
	if dial == nil {
		return errors.New("missing trusted live connection factory")
	}
	if _, err := managedlive.Encode(&ready); err != nil {
		return errors.New("invalid ready receipt")
	}
	// Validate the credential without disclosing it.
	probe := managedlive.StatusRequest{Version: managedlive.Version, Kind: "status", Credential: credential, Binding: ready.Receipt.Bank.Binding}
	if _, err := managedlive.Encode(&probe); err != nil {
		return errors.New("invalid live authentication")
	}
	ctx, cancel := context.WithTimeout(context.Background(), ProfileOperationTimeout)
	defer cancel()
	if err := lockContext(ctx, &s.saveMu); err != nil {
		return errors.New("ready registration deadline")
	}
	defer s.saveMu.Unlock()
	if err := lockContext(ctx, &s.gatesMu); err != nil {
		return errors.New("ready registration deadline")
	}
	defer s.gatesMu.Unlock()
	v, ok := s.registry.Get(sessionID)
	p, managed := s.profiles.(*ManagedProfileProvider)
	b := ready.Receipt.Bank.Binding
	if s.closed || !ok || v.State != session.Running || v.SelectedProfile == nil || !managed || v.SelectedProfile.ProjectID != b.Project || v.SelectedProfile.Name != b.Profile || v.SelectedProfile.ProfileID != ManagedProfileID(b.Project, b.Profile) || v.SelectedProfile.Revision != ready.Receipt.Bank.Revision {
		return errors.New("ready selection mismatch")
	}
	if _, ok := p.bindings[v.SelectedProfile.ProfileID]; !ok {
		return errors.New("managed profile unavailable")
	}
	_, data, err := p.ReadSnapshot(ctx, v.SelectedProfile.ProfileID)
	if err != nil {
		return errors.New("ready snapshot unavailable")
	}
	snapshot, err := config.ParseManagedProfileSnapshot(b.Profile, data)
	if err != nil || snapshot.Revision() != ready.Receipt.Bank.Revision || ctx.Err() != nil {
		return errors.New("ready snapshot superseded")
	}
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	if s.live == nil {
		s.live = make(map[string]*liveBinding)
	}
	if s.live[sessionID] != nil {
		return errors.New("live session already bound")
	}
	for _, old := range s.live {
		if old.binding == b {
			return errors.New("root binding already assigned")
		}
	}
	if len(s.live) >= 128 {
		for id, old := range s.live {
			if old.ctx.Err() != nil {
				delete(s.live, id)
			}
		}
	}
	if len(s.live) >= 128 || s.live[sessionID] != nil {
		return errors.New("live session already bound or limit reached")
	}
	workerCtx, stop := context.WithCancel(context.Background())
	l := &liveBinding{binding: b, credential: credential, dial: dial, predecessor: ready.Receipt.Bank, lastReceipt: ready.Receipt, ctx: workerCtx, cancel: stop, done: make(chan struct{}), queue: make(chan liveOperation, managedLiveQueueLimit), provider: p, exchange: exchangeManagedLive}
	l.status = session.ManagedLiveStatus{Session: b.Session, Project: b.Project, Profile: b.Profile, Generation: b.Generation, SavedRevision: ready.Receipt.Bank.Revision, State: "saved", Sequence: ready.Receipt.Bank.Sequence, EngineDigest: managedlive.EngineDigest, LastConfirmedAt: readyReceivedAt.UTC()}
	s.live[sessionID] = l
	go l.run()
	return nil
}

// saved is called only while the save serialization lock is held and after the
// authenticated CAS response is validated. It never waits for ROOT.
func (s *Server) managedSaved(id, revision string) {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	for _, l := range s.live {
		if l.ctx.Err() != nil || ManagedProfileID(l.binding.Project, l.binding.Profile) != id {
			continue
		}
		l.mu.Lock()
		l.status.SavedRevision = revision
		if l.ordinal == ^uint64(0) {
			l.status.State = "unknown"
			l.mu.Unlock()
			continue
		}
		l.ordinal++
		if l.status.State != "unknown" {
			select {
			case l.queue <- liveOperation{revision: revision, ordinal: l.ordinal}:
				l.status.State = "pending"
			default:
				l.status.State = "not_queued"
			}
		}
		l.mu.Unlock()
	}
}

func (l *liveBinding) run() {
	defer close(l.done)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case op := <-l.queue:
			l.apply(op)
		case <-ticker.C:
			l.checkStatus()
		}
	}
}

func (l *liveBinding) checkStatus() {
	l.mu.Lock()
	if l.status.State == "unknown" {
		l.mu.Unlock()
		return
	}
	expected := l.lastReceipt
	l.mu.Unlock()
	ctx, cancel := context.WithTimeout(l.ctx, managedlive.UpdateTimeout)
	defer cancel()
	request := &managedlive.StatusRequest{Version: managedlive.Version, Kind: "status", Credential: l.credential, Binding: l.binding}
	response, err := l.exchange(ctx, l.dial, request)
	receivedAt := time.Now().UTC()
	status, ok := response.(*managedlive.Status)
	if err != nil || ctx.Err() != nil || !ok || status.Version != managedlive.Version || status.Kind != "status_result" || status.Receipt != expected {
		l.unknown()
		return
	}
	l.mu.Lock()
	if l.status.State != "unknown" && l.ctx.Err() == nil {
		l.status.LastConfirmedAt = receivedAt
	}
	l.mu.Unlock()
}

func (l *liveBinding) apply(op liveOperation) {
	l.mu.Lock()
	if l.status.State == "unknown" || l.ordinal != op.ordinal {
		l.mu.Unlock()
		return
	}
	l.mu.Unlock()
	ctx, cancel := context.WithTimeout(l.ctx, managedlive.UpdateTimeout)
	defer cancel()
	_, data, err := l.provider.ReadSnapshot(ctx, ManagedProfileID(l.binding.Project, l.binding.Profile))
	if err != nil {
		l.unknown()
		return
	}
	snapshot, err := config.ParseManagedProfileSnapshot(l.binding.Profile, data)
	if err != nil {
		l.unknown()
		return
	}
	if snapshot.Revision() != op.revision {
		l.disposition(op, "skipped")
		return
	}
	// ROOT's current file bank cannot acknowledge network enforcement.
	if len(snapshot.Profile().Network) != 0 {
		l.disposition(op, "unsupported_network")
		return
	}
	var id [32]byte
	if _, err = rand.Read(id[:]); err != nil {
		l.unknown()
		return
	}
	l.mu.Lock()
	predecessor := l.predecessor
	l.mu.Unlock()
	if predecessor.Sequence == ^uint64(0) {
		l.unknown()
		return
	}
	request := managedlive.ApplySaved{Version: managedlive.Version, Kind: "apply_saved", Credential: l.credential, Binding: l.binding, RequestID: hex.EncodeToString(id[:]), Sequence: predecessor.Sequence + 1, Revision: op.revision, Predecessor: predecessor}
	l.mu.Lock()
	current := l.ordinal == op.ordinal && l.status.State != "unknown"
	if current {
		l.status.PendingRequestID = request.RequestID
		l.status.PendingSequence = request.Sequence
		l.status.PredecessorSequence = request.Predecessor.Sequence
		l.status.PredecessorRevision = request.Predecessor.Revision
	}
	l.mu.Unlock()
	if !current {
		return
	}
	response, err := l.exchange(ctx, l.dial, &request)
	receivedAt := time.Now().UTC()
	if err != nil || ctx.Err() != nil {
		l.unknown()
		return
	}
	applied, ok := response.(*managedlive.Applied)
	if !ok || applied.Version != managedlive.Version || applied.Kind != "applied" || applied.Receipt.Version != managedlive.Version || applied.Receipt.Phase != "applied" || applied.Receipt.EngineDigest != managedlive.EngineDigest || applied.Receipt.RequestID != request.RequestID || applied.Receipt.Bank.Binding != l.binding || applied.Receipt.Bank.Sequence != request.Sequence || applied.Receipt.Bank.Revision != request.Revision {
		l.unknown()
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ctx.Err() != nil || l.status.State == "unknown" {
		l.status.State = "unknown"
		return
	}
	l.predecessor = applied.Receipt.Bank
	l.lastReceipt = applied.Receipt
	l.status.LastConfirmedAt = receivedAt
	l.status.AppliedRevision = op.revision
	l.status.RequestID = request.RequestID
	l.status.PendingRequestID = ""
	l.status.PendingSequence = 0
	l.status.Sequence = request.Sequence
	if l.ordinal == op.ordinal {
		l.status.State = "applied"
	}
}
func (l *liveBinding) disposition(op liveOperation, state string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.status.State != "unknown" && l.ordinal == op.ordinal {
		l.status.State = state
	}
}
func (l *liveBinding) unknown() { l.mu.Lock(); defer l.mu.Unlock(); l.status.State = "unknown" }
func (s *Server) managedSaveUnknown(id string) {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	for _, l := range s.live {
		if ManagedProfileID(l.binding.Project, l.binding.Profile) == id {
			l.unknown()
		}
	}
}

func (s *Server) liveStatus(id string) *session.ManagedLiveStatus {
	s.liveMu.Lock()
	l := s.live[id]
	s.liveMu.Unlock()
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	v := l.status
	return &v
}
func (s *Server) stopManagedLive(id string) {
	s.liveMu.Lock()
	l := s.live[id]
	s.liveMu.Unlock()
	if l == nil {
		return
	}
	l.cancel()
	<-l.done
	l.unknown()
}
