package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Gobd/syd-guard/internal/config"
)

const profileFixture = `{"version":1,"name":"default","files":[],"network":[]}`

type testProfileProvider struct {
	mu     sync.Mutex
	source ProfileSource
	data   []byte
}

func (p *testProfileProvider) List(context.Context) ([]ProfileSource, error) {
	return []ProfileSource{p.source}, nil
}

func (p *testProfileProvider) ReadSnapshot(_ context.Context, id string) (ProfileSource, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if id != p.source.ID {
		return ProfileSource{}, nil, fmt.Errorf("unknown")
	}
	return p.source, bytes.Clone(p.data), nil
}

func (p *testProfileProvider) Replace(_ context.Context, id, revision string, data []byte) (ProfileSource, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if id != p.source.ID {
		return ProfileSource{}, nil, fmt.Errorf("unknown")
	}
	old, err := config.ParseManagedProfileSnapshot(p.source.Name, p.data)
	if err != nil {
		return ProfileSource{}, nil, err
	}
	if old.Revision() != revision {
		return ProfileSource{}, nil, config.ErrProfileConflict
	}
	p.data = bytes.Clone(data)
	return p.source, bytes.Clone(p.data), nil
}

func profileRequest(h http.Handler, method, path, body string, auth bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth {
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestManagedProfileProviderWorkflow(t *testing.T) {
	server, err := New(strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	provider := &testProfileProvider{source: ProfileSource{ID: "helper-id", Name: "default", Project: "/project", Path: "/protected/default.json", Edit: true}, data: []byte(profileFixture)}
	server.SetProfileProvider(provider)
	h := server.Handler()
	if w := profileRequest(h, "GET", "/api/profiles", "", false); w.Code != 401 {
		t.Fatalf("auth: %d", w.Code)
	}
	w := profileRequest(h, "GET", "/api/profiles", "", true)
	if w.Code != 200 {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	var list []ProfileMetadata
	if err = json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list) != 1 || !list[0].Capabilities.Edit || list[0].Capabilities.Reload || list[0].Capabilities.SavedDecisions {
		t.Fatalf("list: %s %v", w.Body, err)
	}
	old := list[0].Revision
	good := `{"version":1,"name":"default","files":[{"path":"src","access":["read"],"recursive":false}],"network":[]}`
	for _, body := range []string{`{"expected_revision":"` + old + `","expected_revision":"` + old + `","profile":` + good + `}`, `{"expected_revision":"` + old + `","profile":` + good + `,"extra":1}`, `{"expected_revision":"` + old + `","profile":{"version":1,"name":"default","files":[],"network":[],"name":"default"}}`, string([]byte{0xff})} {
		w = profileRequest(h, "PUT", "/api/profiles/helper-id", body, true)
		if w.Code != 422 {
			t.Fatalf("invalid body: %d %s", w.Code, w.Body)
		}
	}
	body := `{"expected_revision":"` + old + `","profile":` + good + `}`
	w = profileRequest(h, "PUT", "/api/profiles/helper-id", body, true)
	if w.Code != 200 {
		t.Fatalf("save %d %s", w.Code, w.Body)
	}
	var outcome profileOutcome
	if err = json.Unmarshal(w.Body.Bytes(), &outcome); err != nil || outcome.Status != "saved" || outcome.Applied || outcome.RetryRequired || outcome.RestartRequired || outcome.Profile.Revision == old {
		t.Fatalf("outcome %s %v", w.Body, err)
	}
	w = profileRequest(h, "PUT", "/api/profiles/helper-id", body, true)
	if w.Code != 409 || !strings.Contains(w.Body.String(), outcome.Profile.Revision) {
		t.Fatalf("conflict %d %s", w.Code, w.Body)
	}
	w = profileRequest(h, "GET", "/api/profiles/helper-id", "", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), outcome.Profile.Revision) {
		t.Fatalf("get %d %s", w.Code, w.Body)
	}
	w = profileRequest(h, "POST", "/api/profiles/helper-id/reload", `{"session_id":"old","expected_revision":"`+outcome.Profile.Revision+`"}`, true)
	if w.Code != 501 || !strings.Contains(w.Body.String(), "unsupported") {
		t.Fatalf("reload %d %s", w.Code, w.Body)
	}
}

type handlerTransport struct{ handler http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	t.handler.ServeHTTP(w, r)
	return w.Result(), nil
}

func TestProfileOperatorClientPreservesConflict(t *testing.T) {
	server, err := New(strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	server.SetProfileProvider(&testProfileProvider{source: ProfileSource{ID: "helper-id", Name: "default", Project: "/project", Path: "/protected/default.json", Edit: true}, data: []byte(profileFixture)})
	client := &Client{token: strings.Repeat("x", 32), http: &http.Client{Transport: handlerTransport{server.Handler()}}}
	_, err = client.Operate(context.Background(), "PUT", "/api/profiles/helper-id", json.RawMessage(`{"expected_revision":"stale","profile":`+profileFixture+`}`))
	var detail *OperatorError
	if !errors.As(err, &detail) || detail.Status != 409 || !strings.Contains(string(detail.Body), `"code":"revision_conflict"`) {
		t.Fatalf("lost conflict: %v", err)
	}
	if _, err := client.Operate(context.Background(), "POST", "/api/sessions/a/events", nil); err == nil {
		t.Fatal("internal event route was allowed")
	}
}

func TestManagedProfileConcurrentCAS(t *testing.T) {
	server, err := New(strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	provider := &testProfileProvider{source: ProfileSource{ID: "helper-id", Name: "default", Project: "/project", Path: "/protected/default.json", Edit: true}, data: []byte(profileFixture)}
	server.SetProfileProvider(provider)
	base, err := config.ParseManagedProfileSnapshot("default", []byte(profileFixture))
	if err != nil {
		t.Fatal(err)
	}
	bodies := []string{
		`{"expected_revision":"` + base.Revision() + `","profile":{"version":1,"name":"default","files":[{"path":"one","access":["read"],"recursive":false}],"network":[]}}`,
		`{"expected_revision":"` + base.Revision() + `","profile":{"version":1,"name":"default","files":[{"path":"two","access":["read"],"recursive":false}],"network":[]}}`,
	}
	codes := make(chan int, 2)
	for _, body := range bodies {
		go func(body string) {
			codes <- profileRequest(server.Handler(), "PUT", "/api/profiles/helper-id", body, true).Code
		}(body)
	}
	first, second := <-codes, <-codes
	if (first != 200 || second != 409) && (first != 409 || second != 200) {
		t.Fatalf("concurrent saves: %d %d", first, second)
	}
}

func TestCandidateDiscoveryUntrustedAndBounded(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "repo", "nested")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(root, "repo", ".sydguard")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(folder, "default.json")
	if err := os.WriteFile(path, []byte(profileFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := New(strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	server.identity = func(int) (string, error) { return "identity", nil }
	if _, err = server.registry.Register(project, "agent", []string{"agent"}, os.Getpid(), "identity"); err != nil {
		t.Fatal(err)
	}
	h := server.Handler()
	w := profileRequest(h, "GET", "/api/profiles", "", true)
	var list []ProfileMetadata
	if err = json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list) != 1 {
		t.Fatalf("list %d %s %v", w.Code, w.Body, err)
	}
	candidate := list[0]
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Authority != "untrusted-candidate" || candidate.Path != resolvedPath || candidate.Capabilities != (ProfileCapabilities{}) {
		t.Fatalf("candidate: %+v", candidate)
	}
	sessions := server.registry.List(false)
	raw, _ := json.Marshal(sessions)
	if strings.Contains(string(raw), `"profile"`) {
		t.Fatalf("candidate became session selection: %s", raw)
	}
	w = profileRequest(h, "GET", "/api/profiles/"+candidate.ID, "", true)
	if w.Code != 200 {
		t.Fatalf("get %d %s", w.Code, w.Body)
	}
	if err = os.WriteFile(path, []byte(profileFixture+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w = profileRequest(h, "GET", "/api/profiles/"+candidate.ID, "", true)
	var changed ProfileRecord
	if err = json.Unmarshal(w.Body.Bytes(), &changed); w.Code != 200 || err != nil || changed.Revision == candidate.Revision {
		t.Fatalf("candidate revision not refreshed: %d %s %v", w.Code, w.Body, err)
	}
	for _, methodPath := range [][2]string{{"PUT", "/api/profiles/" + candidate.ID}, {"POST", "/api/profiles/" + candidate.ID + "/reload"}} {
		w = profileRequest(h, methodPath[0], methodPath[1], `{}`, true)
		if w.Code != 501 {
			t.Fatalf("mutation: %d %s", w.Code, w.Body)
		}
	}
	if w = profileRequest(h, "GET", "/api/profiles/not-a-profile", "", true); w.Code != 404 {
		t.Fatalf("unknown: %d", w.Code)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(root, "other"), path); err != nil {
		t.Fatal(err)
	}
	w = profileRequest(h, "GET", "/api/profiles", "", true)
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("symlink file discovered: %s", w.Body)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(folder); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(root, folder); err != nil {
		t.Fatal(err)
	}
	w = profileRequest(h, "GET", "/api/profiles", "", true)
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("symlink folder discovered: %s", w.Body)
	}
}

func TestProtectedProjectIsNotDiscovered(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", root)
	t.Setenv("HOME", root)
	configPath, err := config.Path()
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(filepath.Dir(configPath), "private-project")
	folder := filepath.Join(project, ".sydguard")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "default.json"), []byte(profileFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := New(strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	server.identity = func(int) (string, error) { return "identity", nil }
	if _, err := server.registry.Register(project, "agent", []string{"agent"}, os.Getpid(), "identity"); err != nil {
		t.Fatal(err)
	}
	w := profileRequest(server.Handler(), "GET", "/api/profiles", "", true)
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("private candidate disclosed: %s", w.Body)
	}
}

func TestOperatorRouteProfileConstraints(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		allowed      bool
	}{{"GET", "/api/profiles", true}, {"GET", "/api/profiles/a-B_2", true}, {"PUT", "/api/profiles/a-B_2", true}, {"POST", "/api/profiles/a-B_2/reload", true}, {"GET", "/api/profiles/a/reload", false}, {"PUT", "/api/profiles/a/b", false}, {"PUT", "/api/profiles/..", false}, {"GET", "/api/profiles/a?x=1", false}, {"POST", "/api/sessions/x/events", false}} {
		if got := OperatorRoute(tc.method, tc.path); got != tc.allowed {
			t.Errorf("%s %s: %v", tc.method, tc.path, got)
		}
	}
}
