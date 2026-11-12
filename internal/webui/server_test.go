package webui

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/controller"
)

func TestProfileBridgeForwardsTypedConflict(t *testing.T) {
	const host = "127.0.0.1:9876"
	token := strings.Repeat("a", 64)
	handler := Handler(host, token, func(_ context.Context, method, path string, body []byte) ([]byte, error) {
		if method != "PUT" || path != "/api/profiles/opaque-id" || string(body) != `{}` {
			t.Fatalf("unexpected operation: %s %s %s", method, path, body)
		}
		return nil, &controller.OperatorError{Status: 409, Body: []byte(`{"error":"conflict","code":"revision_conflict","current_revision":"new"}`)}
	})
	r := httptest.NewRequest("PUT", "http://"+host+"/api/profiles/opaque-id", strings.NewReader(`{}`))
	r.Host = host
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 409 || !strings.Contains(w.Body.String(), `"current_revision":"new"`) {
		t.Fatalf("typed conflict: %d %s", w.Code, w.Body)
	}
}

func TestProfileBridgeIndeterminateAndDeadline(t *testing.T) {
	const host = "127.0.0.1:9876"
	token := strings.Repeat("a", 64)
	for _, mode := range []string{"typed", "lost transport", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			handler := Handler(host, token, func(ctx context.Context, _, _ string, _ []byte) ([]byte, error) {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > controller.OperatorOperationTimeout {
					t.Fatal("bridge did not bound operator work")
				}
				if mode == "typed" {
					return nil, &controller.OperatorError{Status: 503, Body: []byte(`{"error":"may have committed","code":"indeterminate"}`)}
				}
				if mode == "deadline" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return nil, errors.New("lost save response")
			})
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			r := httptest.NewRequest("PUT", "http://"+host+"/api/profiles/opaque-id", strings.NewReader(`{}`)).WithContext(ctx)
			r.Host = host
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != 503 || !strings.Contains(w.Body.String(), `"code":"indeterminate"`) {
				t.Fatalf("uncertain outcome lost: %d %s", w.Code, w.Body)
			}
		})
	}
	if NewServer(nil).WriteTimeout <= controller.OperatorOperationTimeout+2*time.Second {
		t.Fatal("bridge operation/cleanup exceeds HTTP response deadline")
	}
}

func TestProfileTimeoutDoesNotChangeLiveDecisionRoutes(t *testing.T) {
	const host = "127.0.0.1:9876"
	token := strings.Repeat("a", 64)
	handler := Handler(host, token, func(ctx context.Context, _, _ string, _ []byte) ([]byte, error) {
		if _, ok := ctx.Deadline(); ok {
			t.Fatal("profile timeout leaked into live decisions")
		}
		return []byte(`{"status":"applied"}`), nil
	})
	r := httptest.NewRequest("POST", "http://"+host+"/api/network/decisions", strings.NewReader(`{}`))
	r.Host = host
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("live decision: %d %s", w.Code, w.Body)
	}
}

func TestBridgeRejectsCrossOriginRebindingAndAgentRoutes(t *testing.T) {
	const host = "127.0.0.1:9876"
	token := strings.Repeat("a", 64)
	called := false
	handler := Handler(host, token, func(_ context.Context, _, _ string, _ []byte) ([]byte, error) {
		called = true
		return []byte("[]"), nil
	})
	for _, tc := range []struct {
		host, origin, path, auth string
		status                   int
	}{
		{host, "", "/api/files/pending", "", 401},
		{"attacker.example", "", "/api/files/pending", "Bearer " + token, 403},
		{host, "https://attacker.example", "/api/files/pending", "Bearer " + token, 403},
		{host, "", "/api/sessions/new", "Bearer " + token, 404},
		{host, "http://" + host, "/api/files/pending", "Bearer " + token, 200},
	} {
		called = false
		r := httptest.NewRequest("GET", "http://"+host+tc.path, nil)
		r.Host = tc.host
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Authorization", tc.auth)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%+v got %d", tc, w.Code)
		}
		if tc.status != 200 && called {
			t.Fatal("rejected request reached operator API")
		}
	}
}
