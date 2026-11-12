package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type rawRequestTransport func(*http.Request) (*http.Response, error)

func (f rawRequestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOperatorBridgePreservesReviewedProfileBytes(t *testing.T) {
	fixture, ref := newManagedFixture(t)
	provider, err := NewManagedProfileProvider(context.Background(), fixture, []ManagedProfileRef{ref}, true)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("t", 32)
	server, err := New(token)
	if err != nil {
		t.Fatal(err)
	}
	server.SetProfileProvider(provider)
	profile := []byte(`{"version":1,"name":"default","files":[{"path":"/a<b>&` + "\u2028\u2029😀" + `","access":["read"],"recursive":false}],"network":[]}`)
	body := []byte(`{"expected_revision":"` + fixture.response.Revision + `","profile":` + string(profile) + `}`)
	digest := sha256.Sum256(profile)
	wantRevision := hex.EncodeToString(digest[:])
	client := &Client{token: token, http: &http.Client{Transport: rawRequestTransport(func(r *http.Request) (*http.Response, error) {
		got, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			return nil, readErr
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("operator bridge changed reviewed request bytes: got %q, want %q", got, body)
		}
		r.Body = io.NopCloser(bytes.NewReader(got))
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		return w.Result(), nil
	})}}
	data, err := client.Operate(context.Background(), "PUT", "/api/profiles/"+ManagedProfileID(ref.ProjectID, ref.Name), json.RawMessage(body))
	if err != nil {
		t.Fatal(err)
	}
	var outcome profileOutcome
	if err := json.Unmarshal(data, &outcome); err != nil {
		t.Fatal(err)
	}
	if outcome.Status != "saved" || outcome.Applied || outcome.Profile.Revision != wantRevision {
		t.Fatalf("save acknowledgement is not bound to reviewed bytes: %+v", outcome)
	}
	if !bytes.Equal(fixture.response.Profile, profile) || fixture.response.Revision != wantRevision {
		t.Fatal("helper adapter did not receive the exact reviewed profile bytes")
	}
}

func TestClientRejectsMalformedRawRequestBeforeTransport(t *testing.T) {
	called := false
	client := &Client{http: &http.Client{Transport: rawRequestTransport(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})}}
	if err := client.request(context.Background(), "PUT", "/api/profiles/example", json.RawMessage(`{"invalid":`), nil); err == nil || called {
		t.Fatal("malformed raw JSON reached the controller transport")
	}
}
