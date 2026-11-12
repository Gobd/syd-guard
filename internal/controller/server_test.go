package controller

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/files"
	"github.com/Gobd/syd-guard/internal/session"
)

func TestOperatorAuthAndNativeMethods(t *testing.T) {
	server, err := New(strings.Repeat("x", 64))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, auth string
		status             int
	}{
		{"GET", "/api/health", "", 401},
		{"GET", "/api/health", strings.Repeat("x", 64), 401},
		{"GET", "/api/health", "Bearer " + strings.Repeat("x", 64), 200},
		{"POST", "/api/health", "Bearer " + strings.Repeat("x", 64), 405},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.Header.Set("Authorization", tc.auth)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%+v got %d", tc, w.Code)
		}
	}
}

func TestRegisterDerivesIdentityAndRejectsFalseFinish(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process identity is checked in Linux controller")
	}
	token := strings.Repeat("x", 64)
	server, err := New(token)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path string, body any) *httptest.ResponseRecorder {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(data))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		return w
	}
	w := request("POST", "/api/sessions", map[string]any{"project": "/projects/app", "command": []string{"pi", "secret-argument"}, "pid": os.Getpid()})
	if w.Code != 201 {
		t.Fatalf("register %d %s", w.Code, w.Body)
	}
	var registered session.Session
	if err := json.Unmarshal(w.Body.Bytes(), &registered); err != nil {
		t.Fatal(err)
	}
	if registered.StartIdentity == "" || registered.Name != "app" || len(registered.Command) != 1 || registered.ArgumentCount != 1 {
		t.Fatalf("bad identity/redaction: %+v", registered)
	}
	w = request("POST", "/api/sessions/"+registered.ID+"/finish", map[string]string{"start_identity": registered.StartIdentity})
	if w.Code != 409 {
		t.Fatalf("live process marked finished: %d %s", w.Code, w.Body)
	}
	w = request("POST", "/api/sessions", map[string]any{"project": "/projects/app", "command": []string{"pi"}, "pid": os.Getpid(), "start_identity": "fake"})
	if w.Code != 400 {
		t.Fatalf("self-asserted identity accepted: %d", w.Code)
	}
}

func TestFileApprovalAPICannotApproveProtectedMetadata(t *testing.T) {
	token := strings.Repeat("x", 64)
	server, err := New(token)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	secret := filepath.Join(root, ".env")
	if err := os.WriteFile(secret, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.files.Register("run", "test", files.Context{Socket: filepath.Join(root, "syd.sock"), Scopes: []string{root}, PolicyDirectory: filepath.Join(root, ".sydguard")}); err != nil {
		t.Fatal(err)
	}
	request := func(method, path string, body any) *httptest.ResponseRecorder {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(data))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		return w
	}
	for _, capability := range []string{"read", "stat"} {
		if w := request("POST", "/api/sessions/run/events", files.Event{Capability: capability, Action: "deny", Path: secret}); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}
	if w := request("GET", "/api/files/pending", nil); w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("protected requests exposed: %d %s", w.Code, w.Body)
	}
	if w := request("POST", "/api/files/decisions", files.Decision{ID: "forged", Action: "allow", Scope: "run"}); w.Code != 409 {
		t.Fatalf("forged grant accepted: %d %s", w.Code, w.Body)
	}
}
