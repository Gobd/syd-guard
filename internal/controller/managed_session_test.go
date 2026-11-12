package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/session"
)

func TestManagedSessionBinding(t *testing.T) {
	server, err := New(strings.Repeat("x", 64))
	if err != nil {
		t.Fatal(err)
	}
	server.identity = func(int) (string, error) { return "identity", nil }
	projectID := strings.Repeat("a", 64)
	selection := &session.SelectedProfile{ProjectID: projectID, Name: "default", Revision: strings.Repeat("b", 64), ProfileID: ManagedProfileID(projectID, "default"), Provenance: "manual/unknown"}
	input := Registration{Project: "/project", Command: []string{"/bin/echo"}, PID: 12, SelectedProfile: selection}
	post := func() *httptest.ResponseRecorder {
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/sessions", bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 64))
		result := httptest.NewRecorder()
		server.Handler().ServeHTTP(result, req)
		return result
	}
	result := post()
	if result.Code != http.StatusCreated {
		t.Fatalf("registration: %d %s", result.Code, result.Body.String())
	}
	var got session.Session
	if err := json.Unmarshal(result.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.SelectedProfile == nil || *got.SelectedProfile != *selection || got.SelectedProfile.Applied {
		t.Fatalf("bad selected binding: %+v", got.SelectedProfile)
	}
	selection.Revision = strings.Repeat("c", 64)
	stored, ok := server.registry.Get(got.ID)
	if !ok || stored.SelectedProfile.Revision != strings.Repeat("b", 64) {
		t.Fatal("binding not owned")
	}
	selection.ProfileID = "wrong"
	if result := post(); result.Code != http.StatusBadRequest {
		t.Fatalf("invalid binding accepted: %d", result.Code)
	}
	selection.ProfileID = ManagedProfileID(projectID, "default")
	selection.Applied = true
	if result := post(); result.Code != http.StatusBadRequest {
		t.Fatalf("self-asserted applied accepted: %d", result.Code)
	}
}
