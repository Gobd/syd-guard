package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/controller"
)

// memoryProfiles is test-only; it is not a protected store or production provider.
type memoryProfiles struct {
	mu     sync.Mutex
	source controller.ProfileSource
	data   []byte
}

func (p *memoryProfiles) List(context.Context) ([]controller.ProfileSource, error) {
	return []controller.ProfileSource{p.source}, nil
}

func (p *memoryProfiles) ReadSnapshot(_ context.Context, id string) (controller.ProfileSource, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if id != p.source.ID {
		return controller.ProfileSource{}, nil, fmt.Errorf("unknown")
	}
	return p.source, bytes.Clone(p.data), nil
}

func (p *memoryProfiles) Replace(_ context.Context, id, revision string, data []byte) (controller.ProfileSource, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	before, err := config.ParseManagedProfileSnapshot(p.source.Name, p.data)
	if err != nil || id != p.source.ID {
		return controller.ProfileSource{}, nil, fmt.Errorf("unknown")
	}
	if before.Revision() != revision {
		return controller.ProfileSource{}, nil, config.ErrProfileConflict
	}
	p.data = bytes.Clone(data)
	return p.source, bytes.Clone(p.data), nil
}

func TestProfileBridgeWithRealControllerAndSnapshotProvider(t *testing.T) {
	master := strings.Repeat("m", 32)
	uiToken := strings.Repeat("u", 32)
	const host = "127.0.0.1:9876"
	server, err := controller.New(master)
	if err != nil {
		t.Fatal(err)
	}
	server.SetProfileProvider(&memoryProfiles{source: controller.ProfileSource{ID: "test-helper-id", Name: "default", Project: "/test-project", Path: "/test-project/.sydguard/default.json", Edit: true}, data: []byte(`{"version":1,"name":"default","files":[],"network":[]}`)})
	backend := server.Handler()
	bridge := Handler(host, uiToken, func(ctx context.Context, method, path string, data []byte) ([]byte, error) {
		r := httptest.NewRequest(method, "http://controller"+path, bytes.NewReader(data)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+master)
		w := httptest.NewRecorder()
		backend.ServeHTTP(w, r)
		if w.Code >= 400 {
			return nil, &controller.OperatorError{Status: w.Code, Body: bytes.Clone(w.Body.Bytes())}
		}
		return bytes.Clone(w.Body.Bytes()), nil
	})
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
		r.Host = host
		r.Header.Set("Authorization", "Bearer "+uiToken)
		w := httptest.NewRecorder()
		bridge.ServeHTTP(w, r)
		return w
	}
	w := request("GET", "/api/profiles", "")
	var list []controller.ProfileMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || w.Code != 200 || len(list) != 1 || !list[0].Capabilities.Edit {
		t.Fatalf("list %d %s %v", w.Code, w.Body, err)
	}
	w = request("GET", "/api/profiles/test-helper-id", "")
	if w.Code != 200 {
		t.Fatalf("get %d %s", w.Code, w.Body)
	}
	body := `{"expected_revision":"` + list[0].Revision + `","profile":{"version":1,"name":"default","files":[{"path":"src","access":["read"],"recursive":false}],"network":[]}}`
	w = request("PUT", "/api/profiles/test-helper-id", body)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"applied":false`) {
		t.Fatalf("save %d %s", w.Code, w.Body)
	}
	w = request("PUT", "/api/profiles/test-helper-id", body)
	if w.Code != 409 || !strings.Contains(w.Body.String(), `"code":"revision_conflict"`) {
		t.Fatalf("conflict %d %s", w.Code, w.Body)
	}
	w = request("POST", "/api/profiles/test-helper-id/reload", `{"session_id":"old","expected_revision":"`+list[0].Revision+`"}`)
	if w.Code != 501 || !strings.Contains(w.Body.String(), `"code":"unsupported"`) {
		t.Fatalf("reload %d %s", w.Code, w.Body)
	}
}
