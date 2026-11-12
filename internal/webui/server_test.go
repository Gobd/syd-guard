package webui

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

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
