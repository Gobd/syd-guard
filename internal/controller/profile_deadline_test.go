package controller

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/network"
)

func TestProfileHandlersDoNotWaitForSessionCleanup(t *testing.T) {
	server, err := New(strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	provider := &testProfileProvider{source: ProfileSource{ID: "helper-id", Name: "default", Project: "/project", Path: "/project/.sydguard/default.json", Edit: true}, data: []byte(profileFixture)}
	server.SetProfileProvider(provider)
	server.gatesMu.Lock()
	defer server.gatesMu.Unlock()
	for _, path := range []string{"/api/profiles", "/api/profiles/helper-id"} {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer cancel()
		r := httptest.NewRequest("GET", path, nil).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			w := httptest.NewRecorder()
			server.Handler().ServeHTTP(w, r)
			done <- w
		}()
		select {
		case w := <-done:
			if w.Code != 200 {
				t.Fatalf("independent intent handler: %d %s", w.Code, w.Body)
			}
		case <-time.After(time.Second):
			t.Fatal("profile handler waited on session cleanup authority")
		}
	}
}

func TestProfileCandidateLockHonorsCancellation(t *testing.T) {
	server, err := New(strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	server.profilesMu.Lock()
	defer server.profilesMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	r := httptest.NewRequest("GET", "/api/profiles", nil).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("canceled candidate lock: %d %s", w.Code, w.Body)
	}
}

func TestQueuedNetworkDecisionCannotCommitAfterCancellation(t *testing.T) {
	for _, action := range []string{"allow", "deny"} {
		t.Run(action, func(t *testing.T) {
			server, err := New(strings.Repeat("x", 32))
			if err != nil {
				t.Fatal(err)
			}
			target, err := network.Canonical("example.com", 443)
			if err != nil {
				t.Fatal(err)
			}
			server.network.Check("session", "agent", target)
			pending := server.network.Pending()[0]
			server.gates["session"] = nil // proxy presence; no live gateway is needed
			server.gatesMu.Lock()
			defer server.gatesMu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- server.decideNetwork(ctx, network.Decision{ID: pending.ID, Action: action, Scope: "run"})
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("queued decision: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled decision remained queued for authority")
			}
			if requests := server.network.Pending(); len(requests) != 1 || requests[0].ID != pending.ID {
				t.Fatal("canceled decision changed policy or consumed its request")
			}
		})
	}
}
