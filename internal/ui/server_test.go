package ui

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestUIForceOverlay(t *testing.T) {
	for _, fail := range []bool{false, true} {
		remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct{ Session, Path string }
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if r.URL.Path != "/api/overlay" || req.Session != "agent" || req.Path != "/project/target" {
				t.Errorf("wrong request: %s %+v", r.URL.Path, req)
			}
			result := map[string]any{"exit": 0, "stdout": "overlay ready"}
			if fail {
				result = map[string]any{"exit": 1, "error": "mount refused"}
			}
			_ = json.NewEncoder(w).Encode(result)
		}))
		transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, remote.Listener.Addr().String())
		}}
		u := &uiServer{backends: map[string]*backend{"vm": {name: "vm", ok: true, client: &http.Client{Transport: transport}}}}
		req := httptest.NewRequest("POST", URL()+"api/overlay", strings.NewReader(`{"vm":"vm","session":"agent","path":"/project/target"}`))
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		u.routes().ServeHTTP(response, req)
		want := http.StatusOK
		if fail {
			want = http.StatusBadRequest
		}
		if response.Code != want {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		transport.CloseIdleConnections()
		remote.Close()
	}
}

func TestSnapshotBackendConcurrentUpdates(t *testing.T) {
	u := &uiServer{}
	b := &backend{name: "test"}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 10000 {
			u.mu.Lock()
			b.ok, b.err = true, ""
			u.mu.Unlock()
			u.mu.Lock()
			b.ok, b.err = false, "connecting"
			u.mu.Unlock()
		}
	})
	for range 10000 {
		snapshot := u.snapshotBackend(b)
		if snapshot.ok && snapshot.err != "" {
			t.Errorf("inconsistent backend snapshot: %+v", snapshot)
		}
	}
	wg.Wait()
}
