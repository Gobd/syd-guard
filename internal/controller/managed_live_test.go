package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/managedlive"
	"github.com/Gobd/syd-guard/internal/session"
)

func liveFixture(t *testing.T) (*Server, *managedClientFixture, ManagedProfileRef, *liveBinding, string) {
	t.Helper()
	client, ref := newManagedFixture(t)
	provider, err := NewManagedProfileProvider(context.Background(), client, []ManagedProfileRef{ref}, true)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	s.SetProfileProvider(provider)
	v, err := s.registry.Register("/nonexistent-managed-project", "test", []string{"echo"}, 123, "identity")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.registry.SetSelectedProfile(v.ID, session.SelectedProfile{ProjectID: ref.ProjectID, ProfileID: ManagedProfileID(ref.ProjectID, ref.Name), Name: ref.Name, Revision: client.response.Revision})
	if err != nil {
		t.Fatal(err)
	}
	b := managedlive.Binding{Session: strings.Repeat("b", 64), Project: ref.ProjectID, Profile: ref.Name, Generation: 1}
	ready := managedlive.Ready{Version: managedlive.Version, Kind: "ready", Ticket: strings.Repeat("c", 64), Receipt: managedlive.Receipt{Version: managedlive.Version, RequestID: strings.Repeat("d", 64), Phase: "ready", EngineDigest: managedlive.EngineDigest, Bank: managedlive.BankReceipt{Binding: b, Sequence: 1, Revision: client.response.Revision}}}
	dial := func(context.Context) (*net.UnixConn, error) { return nil, errors.New("not used") }
	if err = s.RegisterManagedRootReady(v.ID, ready, time.Now(), strings.Repeat("e", 64), dial); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.stopManagedLive(v.ID) })
	return s, client, ref, s.live[v.ID], v.ID
}
func saveLive(t *testing.T, s *Server, c *managedClientFixture, ref ManagedProfileRef, body string) int {
	t.Helper()
	c.mu.Lock()
	revision := c.response.Revision
	c.mu.Unlock()
	data := `{"expected_revision":"` + revision + `","profile":` + body + `}`
	return profileRequest(s.Handler(), "PUT", "/api/profiles/"+ManagedProfileID(ref.ProjectID, ref.Name), data, true).Code
}
func waitLive(t *testing.T, s *Server, id, state string) session.ManagedLiveStatus {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := s.liveStatus(id)
		if status != nil && status.State == state {
			return *status
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("status wanted %s, got %+v", state, s.liveStatus(id))
	return session.ManagedLiveStatus{}
}

const liveProfile1 = `{"version":1,"name":"default","files":[{"path":"src","access":["read"],"recursive":false}],"network":[]}`
const liveProfile2 = `{"version":1,"name":"default","files":[{"path":"src","access":["write"],"recursive":false}],"network":[]}`

func TestManagedLiveSaveQueuesAndRequiresExactApplied(t *testing.T) {
	s, c, ref, l, id := liveFixture(t)
	requests := make(chan managedlive.ApplySaved, 1)
	release := make(chan struct{})
	l.exchange = func(ctx context.Context, _ ManagedLiveDial, request any) (any, error) {
		r := request.(*managedlive.ApplySaved)
		requests <- *r
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &managedlive.Applied{Version: managedlive.Version, Kind: "applied", Receipt: managedlive.Receipt{Version: managedlive.Version, RequestID: r.RequestID, Phase: "applied", EngineDigest: managedlive.EngineDigest, Bank: managedlive.BankReceipt{Binding: r.Binding, Sequence: r.Sequence, Revision: r.Revision}}}, nil
	}
	if code := saveLive(t, s, c, ref, liveProfile1); code != 200 {
		t.Fatal(code)
	}
	req := <-requests
	pending := waitLive(t, s, id, "pending")
	if pending.AppliedRevision != "" || req.Predecessor.Sequence != 1 || req.Sequence != 2 || req.Binding != l.binding || req.Revision != pending.SavedRevision {
		t.Fatalf("bad request or pending state: %+v %+v", req, pending)
	}
	output, _ := json.Marshal(pending)
	if strings.Contains(string(output), req.Credential) {
		t.Fatal("credential leaked")
	}
	close(release)
	applied := waitLive(t, s, id, "applied")
	if applied.RequestID != req.RequestID || applied.AppliedRevision != req.Revision || applied.Sequence != req.Sequence {
		t.Fatal(applied)
	}
}
func TestManagedLiveLostAckStickyUnknownAndNoRetry(t *testing.T) {
	s, c, ref, l, id := liveFixture(t)
	calls := make(chan struct{}, 4)
	l.exchange = func(context.Context, ManagedLiveDial, any) (any, error) {
		calls <- struct{}{}
		return nil, errors.New("lost ack")
	}
	if code := saveLive(t, s, c, ref, liveProfile1); code != 200 {
		t.Fatal(code)
	}
	waitLive(t, s, id, "unknown")
	if code := saveLive(t, s, c, ref, liveProfile2); code != 200 {
		t.Fatal(code)
	}
	waitLive(t, s, id, "unknown")
	if len(calls) != 1 {
		t.Fatalf("unexpected retry: %d", len(calls))
	}
}
func TestManagedLiveNetworkSavedOnly(t *testing.T) {
	s, c, ref, l, id := liveFixture(t)
	calls := make(chan struct{}, 1)
	l.exchange = func(context.Context, ManagedLiveDial, any) (any, error) {
		calls <- struct{}{}
		return nil, nil
	}
	profile := `{"version":1,"name":"default","files":[],"network":[{"host":"example.com","port":443,"transport":"tcp"}]}`
	if code := saveLive(t, s, c, ref, profile); code != 200 {
		t.Fatal(code)
	}
	status := waitLive(t, s, id, "unsupported_network")
	if status.AppliedRevision != "" || len(calls) != 0 {
		t.Fatal(status)
	}
}
func TestManagedLiveMismatchedReceiptUnknown(t *testing.T) {
	s, c, ref, l, id := liveFixture(t)
	l.exchange = func(_ context.Context, _ ManagedLiveDial, request any) (any, error) {
		r := request.(*managedlive.ApplySaved)
		return &managedlive.Applied{Version: managedlive.Version, Kind: "applied", Receipt: managedlive.Receipt{Version: managedlive.Version, RequestID: r.RequestID, Phase: "applied", EngineDigest: managedlive.EngineDigest, Bank: managedlive.BankReceipt{Binding: r.Binding, Sequence: r.Sequence, Revision: strings.Repeat("f", 64)}}}, nil
	}
	if code := saveLive(t, s, c, ref, liveProfile1); code != 200 {
		t.Fatal(code)
	}
	status := waitLive(t, s, id, "unknown")
	if status.AppliedRevision != "" {
		t.Fatal(status)
	}
}
