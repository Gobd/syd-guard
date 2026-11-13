package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/managedlive"
	"github.com/Gobd/syd-guard/internal/session"
)

func TestManagedSelectionRejectsLegacyFileLearning(t *testing.T) {
	s, _, _, _, id := liveFixture(t)
	result := profileRequest(s.Handler(), "POST", "/api/sessions/"+id+"/files", `{}`, true)
	if result.Code != 409 || !strings.Contains(result.Body.String(), "legacy file learning") {
		t.Fatal(result.Code, result.Body.String())
	}
	if len(s.files.Pending()) != 0 {
		t.Fatal("managed selection acquired legacy pending events")
	}
}

func TestManagedLiveStatusRequiresExactLastReceipt(t *testing.T) {
	s, _, _, l, id := liveFixture(t)
	l.mu.Lock()
	expected := l.lastReceipt
	l.mu.Unlock()
	l.exchange = func(_ context.Context, _ ManagedLiveDial, request any) (any, error) {
		if _, ok := request.(*managedlive.StatusRequest); !ok {
			t.Fatal("expected status request")
		}
		return &managedlive.Status{Version: managedlive.Version, Kind: "status_result", Receipt: expected}, nil
	}
	l.checkStatus()
	waitLive(t, s, id, "saved")
	expected.RequestID = strings.Repeat("f", 64)
	l.checkStatus()
	waitLive(t, s, id, "unknown")
}

func TestManagedLiveStatusUnavailableIsSticky(t *testing.T) {
	s, c, ref, l, id := liveFixture(t)
	calls := 0
	l.exchange = func(context.Context, ManagedLiveDial, any) (any, error) {
		calls++
		return nil, errors.New("unavailable")
	}
	l.checkStatus()
	waitLive(t, s, id, "unknown")
	l.checkStatus()
	if code := saveLive(t, s, c, ref, liveProfile1); code != 200 {
		t.Fatal(code)
	}
	if calls != 1 {
		t.Fatalf("unknown status was retried: %d", calls)
	}
}

func TestManagedLiveABARequiresNewReceipt(t *testing.T) {
	s, c, ref, l, id := liveFixture(t)
	requests := make(chan managedlive.ApplySaved, 3)
	release := make(chan struct{}, 3)
	l.exchange = func(ctx context.Context, _ ManagedLiveDial, v any) (any, error) {
		r := v.(*managedlive.ApplySaved)
		requests <- *r
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &managedlive.Applied{Version: managedlive.Version, Kind: "applied", Receipt: managedlive.Receipt{Version: managedlive.Version, RequestID: r.RequestID, Phase: "applied", EngineDigest: managedlive.EngineDigest, Bank: managedlive.BankReceipt{Binding: r.Binding, Sequence: r.Sequence, Revision: r.Revision}}}, nil
	}
	if saveLive(t, s, c, ref, liveProfile1) != 200 {
		t.Fatal("first save")
	}
	first := <-requests
	if saveLive(t, s, c, ref, liveProfile2) != 200 || saveLive(t, s, c, ref, liveProfile1) != 200 {
		t.Fatal("ABA saves")
	}
	release <- struct{}{}
	var latest managedlive.ApplySaved
	select {
	case latest = <-requests:
	case <-time.After(2 * time.Second):
		t.Fatal("latest was not submitted")
	}
	if latest.Revision != first.Revision || latest.RequestID == first.RequestID || latest.Predecessor.Sequence != first.Sequence {
		t.Fatalf("incorrect ABA operation: %+v %+v", first, latest)
	}
	state := waitLive(t, s, id, "pending")
	if state.RequestID != first.RequestID {
		t.Fatal("historical receipt was confused with latest", state)
	}
	release <- struct{}{}
	state = waitLive(t, s, id, "applied")
	if state.RequestID != latest.RequestID || state.Sequence != latest.Sequence {
		t.Fatal(state)
	}
}

func TestManagedLiveReadyMustMatchCurrentSnapshot(t *testing.T) {
	s, c, ref, l, _ := liveFixture(t)
	l.mu.Lock()
	oldBank := l.lastReceipt.Bank
	l.mu.Unlock()
	v, err := s.registry.Register("/nonexistent-managed-project", "second", []string{"echo"}, 124, "identity")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.registry.SetSelectedProfile(v.ID, session.SelectedProfile{ProjectID: ref.ProjectID, ProfileID: ManagedProfileID(ref.ProjectID, ref.Name), Name: ref.Name, Revision: oldBank.Revision})
	if err != nil {
		t.Fatal(err)
	}
	// A stale Ready cannot be published after a newer authenticated CAS.
	if saveLive(t, s, c, ref, liveProfile1) != 200 {
		t.Fatal("save")
	}
	b := l.binding
	ready := managedlive.Ready{Version: managedlive.Version, Kind: "ready", Ticket: strings.Repeat("c", 64), Receipt: managedlive.Receipt{Version: managedlive.Version, RequestID: strings.Repeat("d", 64), Phase: "ready", EngineDigest: managedlive.EngineDigest, Bank: oldBank}}
	ready.Receipt.Bank.Binding = b
	if err := s.RegisterManagedRootReady(v.ID, ready, time.Now(), strings.Repeat("e", 64), l.dial); err == nil {
		t.Fatal("stale ready accepted")
	}
}

func TestManagedLiveQueueOverflowDoesNotClaimLatestApplied(t *testing.T) {
	s, c, ref, l, id := liveFixture(t)
	requests := make(chan struct{}, 16)
	release := make(chan struct{})
	l.exchange = func(ctx context.Context, _ ManagedLiveDial, v any) (any, error) {
		r := v.(*managedlive.ApplySaved)
		requests <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &managedlive.Applied{Version: managedlive.Version, Kind: "applied", Receipt: managedlive.Receipt{Version: managedlive.Version, RequestID: r.RequestID, Phase: "applied", EngineDigest: managedlive.EngineDigest, Bank: managedlive.BankReceipt{Binding: r.Binding, Sequence: r.Sequence, Revision: r.Revision}}}, nil
	}
	if saveLive(t, s, c, ref, liveProfile1) != 200 {
		t.Fatal("first save")
	}
	<-requests
	for i := 0; i < managedLiveQueueLimit+1; i++ {
		profile := fmt.Sprintf(`{"version":1,"name":"default","files":[{"path":"src%d","access":["read"],"recursive":false}],"network":[]}`, i)
		if saveLive(t, s, c, ref, profile) != 200 {
			t.Fatal("queued save")
		}
	}
	waitLive(t, s, id, "not_queued")
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for len(l.queue) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	status := waitLive(t, s, id, "not_queued")
	if status.AppliedRevision == status.SavedRevision || len(requests) != 0 {
		t.Fatal("overflow falsely applied or retried", status)
	}
}

func TestManagedLiveStopCancelsAndJoinsWorker(t *testing.T) {
	s, c, ref, l, id := liveFixture(t)
	started := make(chan struct{})
	l.exchange = func(ctx context.Context, _ ManagedLiveDial, _ any) (any, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if saveLive(t, s, c, ref, liveProfile1) != 200 {
		t.Fatal("save")
	}
	<-started
	s.stopManagedLive(id)
	select {
	case <-l.done:
	default:
		t.Fatal("worker not joined")
	}
	waitLive(t, s, id, "unknown")
}

func TestManagedLiveStatusSerializesUint64Exactly(t *testing.T) {
	_, _, _, l, _ := liveFixture(t)
	l.mu.Lock()
	l.status.Generation = ^uint64(0)
	l.status.Sequence = ^uint64(0)
	value := l.status
	l.mu.Unlock()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"generation":"18446744073709551615"`) || !strings.Contains(string(b), `"sequence":"18446744073709551615"`) {
		t.Fatal(string(b))
	}
}

func liveSecondSession(t *testing.T, s *Server, ref ManagedProfileRef, l *liveBinding) (string, managedlive.Ready) {
	t.Helper()
	v, err := s.registry.Register("/nonexistent-managed-project", "second", []string{"echo"}, 124, "identity")
	if err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	receipt := l.lastReceipt
	l.mu.Unlock()
	if _, err = s.registry.SetSelectedProfile(v.ID, session.SelectedProfile{ProjectID: ref.ProjectID, ProfileID: ManagedProfileID(ref.ProjectID, ref.Name), Name: ref.Name, Revision: receipt.Bank.Revision}); err != nil {
		t.Fatal(err)
	}
	return v.ID, managedlive.Ready{Version: managedlive.Version, Kind: "ready", Ticket: strings.Repeat("c", 64), Receipt: receipt}
}

func TestManagedLiveReadyBindingUniqueIncludingStopped(t *testing.T) {
	s, _, ref, l, id := liveFixture(t)
	second, ready := liveSecondSession(t, s, ref, l)
	register := func(r managedlive.Ready) error {
		return s.RegisterManagedRootReady(second, r, time.Now(), strings.Repeat("e", 64), l.dial)
	}
	if err := register(ready); err == nil {
		t.Fatal("duplicate active binding accepted")
	}
	s.stopManagedLive(id)
	if err := register(ready); err == nil {
		t.Fatal("duplicate stopped binding accepted")
	}
	s.liveMu.Lock()
	n := len(s.live)
	s.liveMu.Unlock()
	if n != 1 {
		t.Fatalf("duplicate worker published: %d", n)
	}
	ready.Receipt.Bank.Binding.Session = strings.Repeat("a", 64)
	if err := register(ready); err != nil {
		t.Fatalf("distinct binding with shared credential: %v", err)
	}
	t.Cleanup(func() { s.stopManagedLive(second) })
}

func TestManagedLiveReadyDeadlineReleasesSaveLock(t *testing.T) {
	s, _, ref, l, _ := liveFixture(t)
	second, ready := liveSecondSession(t, s, ref, l)
	ready.Receipt.Bank.Binding.Session = strings.Repeat("a", 64)
	s.gatesMu.Lock()
	result := make(chan error, 1)
	go func() {
		result <- s.RegisterManagedRootReady(second, ready, time.Now(), strings.Repeat("e", 64), l.dial)
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("registration succeeded")
		}
	case <-time.After(ProfileOperationTimeout + 2*time.Second):
		s.gatesMu.Unlock()
		t.Fatal("deadline failed while lifecycle lock held")
	}
	if !s.saveMu.TryLock() {
		s.gatesMu.Unlock()
		t.Fatal("save lock retained")
	}
	s.saveMu.Unlock()
	s.liveMu.Lock()
	n := len(s.live)
	s.liveMu.Unlock()
	s.gatesMu.Unlock()
	if n != 1 {
		t.Fatal("worker published after deadline")
	}
}

func TestManagedLiveReadyClosedOrEndedSessionRejected(t *testing.T) {
	for _, mode := range []string{"closed", "ended"} {
		t.Run(mode, func(t *testing.T) {
			s, _, ref, l, _ := liveFixture(t)
			second, ready := liveSecondSession(t, s, ref, l)
			ready.Receipt.Bank.Binding.Session = strings.Repeat("a", 64)
			if mode == "closed" {
				s.gatesMu.Lock()
				s.closed = true
				s.gatesMu.Unlock()
			} else if err := s.registry.Finish(second, "identity"); err != nil {
				t.Fatal(err)
			}
			if err := s.RegisterManagedRootReady(second, ready, time.Now(), strings.Repeat("e", 64), l.dial); err == nil {
				t.Fatal("invalid lifecycle accepted")
			}
			s.liveMu.Lock()
			n := len(s.live)
			s.liveMu.Unlock()
			if n != 1 {
				t.Fatal("worker published")
			}
		})
	}
}

func TestManagedLiveOrdinalSaturationKeepsSavedAndRejectsHistoricalReceipt(t *testing.T) {
	s, c, ref, l, id := liveFixture(t)
	started := make(chan struct{})
	release := make(chan struct{})
	calls := make(chan struct{}, 2)
	l.exchange = func(ctx context.Context, _ ManagedLiveDial, v any) (any, error) {
		r := v.(*managedlive.ApplySaved)
		calls <- struct{}{}
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &managedlive.Applied{Version: managedlive.Version, Kind: "applied", Receipt: managedlive.Receipt{Version: managedlive.Version, RequestID: r.RequestID, Phase: "applied", EngineDigest: managedlive.EngineDigest, Bank: managedlive.BankReceipt{Binding: r.Binding, Sequence: r.Sequence, Revision: r.Revision}}}, nil
	}
	if saveLive(t, s, c, ref, liveProfile1) != 200 {
		t.Fatal("save")
	}
	<-started
	l.mu.Lock()
	l.ordinal = ^uint64(0)
	l.mu.Unlock()
	if saveLive(t, s, c, ref, liveProfile2) != 200 {
		t.Fatal("save at saturation")
	}
	status := waitLive(t, s, id, "unknown")
	c.mu.Lock()
	saved := c.response.Revision
	c.mu.Unlock()
	if status.SavedRevision != saved || len(l.queue) != 0 {
		t.Fatal(status)
	}
	close(release)
	s.stopManagedLive(id)
	l.mu.Lock()
	ordinal := l.ordinal
	l.mu.Unlock()
	status = *s.liveStatus(id)
	if ordinal != ^uint64(0) || status.AppliedRevision != "" || len(calls) != 1 {
		t.Fatal(ordinal, status, len(calls))
	}
}

func TestManagedLiveLastConfirmedTimestampStickyAfterFailure(t *testing.T) {
	s, c, ref, l, id := liveFixture(t)
	calls := 0
	l.exchange = func(_ context.Context, _ ManagedLiveDial, v any) (any, error) {
		calls++
		switch r := v.(type) {
		case *managedlive.ApplySaved:
			return &managedlive.Applied{Version: managedlive.Version, Kind: "applied", Receipt: managedlive.Receipt{Version: managedlive.Version, RequestID: r.RequestID, Phase: "applied", EngineDigest: managedlive.EngineDigest, Bank: managedlive.BankReceipt{Binding: r.Binding, Sequence: r.Sequence, Revision: r.Revision}}}, nil
		case *managedlive.StatusRequest:
			if calls > 2 {
				return nil, errors.New("unavailable")
			}
			l.mu.Lock()
			receipt := l.lastReceipt
			l.mu.Unlock()
			return &managedlive.Status{Version: managedlive.Version, Kind: "status_result", Receipt: receipt}, nil
		}
		return nil, errors.New("unexpected")
	}
	before := time.Now()
	if saveLive(t, s, c, ref, liveProfile1) != 200 {
		t.Fatal("save")
	}
	applied := waitLive(t, s, id, "applied")
	if applied.LastConfirmedAt.Before(before) {
		t.Fatal(applied)
	}
	l.checkStatus()
	cached := *s.liveStatus(id)
	if cached.State != "applied" || cached.LastConfirmedAt.Before(applied.LastConfirmedAt) {
		t.Fatal(cached)
	}
	data, _ := json.Marshal(cached)
	if strings.Contains(string(data), l.credential) {
		t.Fatal("credential leaked")
	}
	l.checkStatus()
	unknown := waitLive(t, s, id, "unknown")
	l.checkStatus()
	if unknown.LastConfirmedAt != cached.LastConfirmedAt || calls != 3 || s.liveStatus(id).State != "unknown" {
		t.Fatal(unknown, calls)
	}
}

func TestManagedLiveGenerationMismatchReceiptUnknown(t *testing.T) {
	s, c, ref, l, id := liveFixture(t)
	l.exchange = func(_ context.Context, _ ManagedLiveDial, v any) (any, error) {
		r := v.(*managedlive.ApplySaved)
		binding := r.Binding
		binding.Generation++
		return &managedlive.Applied{Version: managedlive.Version, Kind: "applied", Receipt: managedlive.Receipt{Version: managedlive.Version, RequestID: r.RequestID, Phase: "applied", EngineDigest: managedlive.EngineDigest, Bank: managedlive.BankReceipt{Binding: binding, Sequence: r.Sequence, Revision: r.Revision}}}, nil
	}
	if saveLive(t, s, c, ref, liveProfile1) != 200 {
		t.Fatal("save")
	}
	if waitLive(t, s, id, "unknown").AppliedRevision != "" {
		t.Fatal("wrong generation applied")
	}
}
