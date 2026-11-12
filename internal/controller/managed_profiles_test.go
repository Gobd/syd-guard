package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/managedstore"
)

type managedClientFixture struct {
	mu           sync.Mutex
	response     managedstore.Response
	readError    error
	replaceError error
	alterSave    func(*managedstore.Response)
	reads, saves int
	lastRef      ManagedProfileRef
}

func copyHelperResponse(r managedstore.Response) managedstore.Response {
	r.Profile = bytes.Clone(r.Profile)
	if r.Namespace != nil {
		namespace := *r.Namespace
		r.Namespace = &namespace
	}
	return r
}

func (f *managedClientFixture) Read(_ context.Context, project, name string) (managedstore.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	f.lastRef = ManagedProfileRef{ProjectID: project, Name: name}
	return copyHelperResponse(f.response), f.readError
}

func (f *managedClientFixture) Replace(_ context.Context, project, name, revision string, data json.RawMessage) (managedstore.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saves++
	f.lastRef = ManagedProfileRef{ProjectID: project, Name: name}
	if f.replaceError != nil {
		return managedstore.Response{}, f.replaceError
	}
	if project != f.response.Project || name != f.response.Name {
		return managedstore.Response{}, fmt.Errorf("unknown registered profile")
	}
	if revision != f.response.Revision {
		return managedstore.Response{}, managedstore.ErrConflict
	}
	snapshot, err := config.ParseManagedProfileSnapshot(name, data)
	if err != nil {
		return managedstore.Response{}, err
	}
	f.response.Profile, f.response.Revision = snapshot.Bytes(), snapshot.Revision()
	response := copyHelperResponse(f.response)
	if f.alterSave != nil {
		f.alterSave(&response)
	}
	return response, nil
}

func newManagedFixture(t *testing.T) (*managedClientFixture, ManagedProfileRef) {
	t.Helper()
	ref := ManagedProfileRef{ProjectID: strings.Repeat("a", 64), Name: "default"}
	snapshot, err := config.ParseManagedProfileSnapshot(ref.Name, []byte(profileFixture))
	if err != nil {
		t.Fatal(err)
	}
	return &managedClientFixture{response: managedstore.Response{
		Project: ref.ProjectID, Name: ref.Name, Profile: snapshot.Bytes(), Revision: snapshot.Revision(),
		// Intentionally nonexistent: the adapter must not reopen metadata paths.
		Namespace: &managedstore.ProjectNamespace{Path: "/nonexistent-managed-project", ProjectDev: 1, ProjectIno: 2, PolicyDev: 1, PolicyIno: 3},
	}}, ref
}

func TestManagedAdapterSnapshotAndCAS(t *testing.T) {
	ctx := context.Background()
	client, ref := newManagedFixture(t)
	provider, err := NewManagedProfileProvider(ctx, client, []ManagedProfileRef{ref}, true)
	if err != nil {
		t.Fatal(err)
	}
	list, err := provider.List(ctx)
	if err != nil || len(list) != 1 || !list[0].Edit {
		t.Fatalf("list: %+v %v", list, err)
	}
	source := list[0]
	list[0].Project = "/forged"
	current, data, err := provider.ReadSnapshot(ctx, source.ID)
	if err != nil || current != source || !bytes.Equal(data, client.response.Profile) || client.lastRef != ref {
		t.Fatalf("snapshot: %+v %s %v", current, data, err)
	}
	data[0] = '['
	if client.response.Profile[0] != '{' {
		t.Fatal("returned snapshot aliases client bytes")
	}
	stable, err := NewManagedProfileProvider(ctx, client, []ManagedProfileRef{ref}, true)
	if err != nil || stable.order[0] != source.ID {
		t.Fatalf("unstable opaque profile ID: %v", err)
	}
	server, err := New(strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	server.SetProfileProvider(provider)
	base := client.response.Revision
	body := `{"expected_revision":"` + base + `","profile":{"version":1,"name":"default","files":[{"path":"src","access":["read"],"recursive":true}],"network":[]}}`
	w := profileRequest(server.Handler(), "PUT", "/api/profiles/"+source.ID, body, true)
	if w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	var outcome profileOutcome
	if err := json.Unmarshal(w.Body.Bytes(), &outcome); err != nil || outcome.Applied || outcome.Profile.Capabilities.Reload || outcome.Profile.Capabilities.SavedDecisions {
		t.Fatalf("save activated permissions: %s %v", w.Body, err)
	}
	if _, _, err := provider.Replace(ctx, source.ID, base, []byte(profileFixture)); !errors.Is(err, config.ErrProfileConflict) {
		t.Fatalf("lost helper CAS conflict: %v", err)
	}
	w = profileRequest(server.Handler(), "PUT", "/api/profiles/"+source.ID, body, true)
	if w.Code != 409 || !strings.Contains(w.Body.String(), client.response.Revision) {
		t.Fatalf("HTTP conflict: %d %s", w.Code, w.Body)
	}
	reads, saves := client.reads, client.saves
	if _, _, err := provider.ReadSnapshot(ctx, "unlisted"); err == nil {
		t.Fatal("unlisted ID resolved")
	}
	if _, _, err := provider.Replace(ctx, "unlisted", base, []byte(profileFixture)); err == nil {
		t.Fatal("unlisted ID saved")
	}
	if client.reads != reads || client.saves != saves {
		t.Fatal("unknown ID reached helper")
	}
}

func TestManagedAdapterRejectsInvalidRegistration(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		mutate func(*managedClientFixture, *ManagedProfileRef)
	}{
		{"bad reference", func(_ *managedClientFixture, r *ManagedProfileRef) { r.ProjectID = "guessed-path" }},
		{"mismatched ID", func(f *managedClientFixture, _ *ManagedProfileRef) { f.response.Project = strings.Repeat("b", 64) }},
		{"mismatched name", func(f *managedClientFixture, _ *ManagedProfileRef) { f.response.Name = "other" }},
		{"missing namespace", func(f *managedClientFixture, _ *ManagedProfileRef) { f.response.Namespace = nil }},
		{"control path", func(f *managedClientFixture, _ *ManagedProfileRef) { f.response.Namespace.Path += "\t" }},
		{"different filesystem", func(f *managedClientFixture, _ *ManagedProfileRef) { f.response.Namespace.PolicyDev++ }},
		{"bad revision", func(f *managedClientFixture, _ *ManagedProfileRef) { f.response.Revision = strings.Repeat("0", 64) }},
		{"failed authentication", func(f *managedClientFixture, _ *ManagedProfileRef) { f.readError = errors.New("credential rejected") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, ref := newManagedFixture(t)
			tc.mutate(client, &ref)
			if _, err := NewManagedProfileProvider(ctx, client, []ManagedProfileRef{ref}, true); err == nil {
				t.Fatal("accepted invalid registration")
			}
		})
	}
	client, ref := newManagedFixture(t)
	if _, err := NewManagedProfileProvider(ctx, client, []ManagedProfileRef{ref, ref}, true); err == nil || client.reads != 0 {
		t.Fatal("duplicate reference accepted or reached helper")
	}
	invalid := ref
	invalid.Name = "../invalid"
	if _, err := NewManagedProfileProvider(ctx, client, []ManagedProfileRef{ref, invalid}, true); err == nil || client.reads != 0 {
		t.Fatal("invalid reference reached helper before complete validation")
	}
	if _, err := NewManagedProfileProvider(ctx, client, nil, true); err == nil {
		t.Fatal("empty catalog accepted")
	}
	if _, err := NewManagedProfileProvider(ctx, client, make([]ManagedProfileRef, 129), true); err == nil {
		t.Fatal("unbounded catalog accepted")
	}
}

func TestManagedAdapterBindingChangesAndIndeterminateSave(t *testing.T) {
	ctx := context.Background()
	for _, mutate := range []func(*managedstore.Response){
		func(r *managedstore.Response) { r.Namespace.Path = "/replacement" },
		func(r *managedstore.Response) { r.Namespace.ProjectIno++ },
		func(r *managedstore.Response) { r.Namespace.PolicyIno++ },
		func(r *managedstore.Response) { r.Project = strings.Repeat("b", 64) },
		func(r *managedstore.Response) { r.Profile = append(r.Profile, '\n') },
	} {
		client, ref := newManagedFixture(t)
		provider, err := NewManagedProfileProvider(ctx, client, []ManagedProfileRef{ref}, true)
		if err != nil {
			t.Fatal(err)
		}
		id, base := provider.order[0], client.response.Revision
		client.alterSave = mutate
		if _, _, err := provider.Replace(ctx, id, base, []byte(profileFixture)); !errors.Is(err, managedstore.ErrIndeterminate) {
			t.Fatalf("mutation binding mismatch not indeterminate: %v", err)
		}
		if client.saves != 1 {
			t.Fatal("indeterminate save automatically retried")
		}
		mutate(&client.response)
		if _, _, err := provider.ReadSnapshot(ctx, id); err == nil {
			t.Fatal("read accepted changed binding/snapshot")
		}
	}
	client, ref := newManagedFixture(t)
	provider, err := NewManagedProfileProvider(ctx, client, []ManagedProfileRef{ref}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.Replace(ctx, provider.order[0], client.response.Revision, []byte(profileFixture)); err == nil || client.saves != 0 {
		t.Fatal("read-only adapter reached mutation helper")
	}
}

func TestManagedAdapterLongDisplayPath(t *testing.T) {
	client, ref := newManagedFixture(t)
	client.response.Namespace.Path = "/" + strings.Repeat("a", 4095)
	provider, err := NewManagedProfileProvider(context.Background(), client, []ManagedProfileRef{ref}, false)
	if err != nil {
		t.Fatalf("valid maximum-length project cannot be displayed: %v", err)
	}
	list, err := provider.List(context.Background())
	if err != nil || len(list) != 1 || len(list[0].Path) <= 4096 {
		t.Fatalf("long display metadata: %+v %v", list, err)
	}
}

func TestManagedAdapterHTTPIndeterminate(t *testing.T) {
	client, ref := newManagedFixture(t)
	provider, err := NewManagedProfileProvider(context.Background(), client, []ManagedProfileRef{ref}, true)
	if err != nil {
		t.Fatal(err)
	}
	client.replaceError = managedstore.ErrIndeterminate
	server, err := New(strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	server.SetProfileProvider(provider)
	body := `{"expected_revision":"` + client.response.Revision + `","profile":` + profileFixture + `}`
	w := profileRequest(server.Handler(), "PUT", "/api/profiles/"+provider.order[0], body, true)
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"code":"indeterminate"`) || client.saves != 1 {
		t.Fatalf("uncertain helper outcome lost: %d %s calls=%d", w.Code, w.Body, client.saves)
	}
	w = profileRequest(server.Handler(), "GET", "/api/profiles/"+provider.order[0], "", true)
	if w.Code != 200 {
		t.Fatalf("authenticated reconciliation read: %d %s", w.Code, w.Body)
	}
}

type stalledManagedClient struct {
	*managedClientFixture
	stallRead, stallSave bool
	deadline             time.Time
}

func (f *stalledManagedClient) Read(ctx context.Context, project, name string) (managedstore.Response, error) {
	f.deadline, _ = ctx.Deadline()
	if f.stallRead {
		<-ctx.Done()
		return managedstore.Response{}, ctx.Err()
	}
	return f.managedClientFixture.Read(ctx, project, name)
}

func (f *stalledManagedClient) Replace(ctx context.Context, project, name, revision string, data json.RawMessage) (managedstore.Response, error) {
	f.deadline, _ = ctx.Deadline()
	if f.stallSave {
		<-ctx.Done()
		return managedstore.Response{}, managedstore.ErrIndeterminate
	}
	return f.managedClientFixture.Replace(ctx, project, name, revision, data)
}

func TestManagedAdapterSharedDeadline(t *testing.T) {
	for _, method := range []string{"GET", "PUT"} {
		t.Run(method, func(t *testing.T) {
			fixture, ref := newManagedFixture(t)
			client := &stalledManagedClient{managedClientFixture: fixture}
			provider, err := NewManagedProfileProvider(context.Background(), client, []ManagedProfileRef{ref}, true)
			if err != nil {
				t.Fatal(err)
			}
			if client.deadline.IsZero() || time.Until(client.deadline) > ProfileOperationTimeout {
				t.Fatal("constructor helper work was not bounded")
			}
			server, err := New(strings.Repeat("x", 32))
			if err != nil {
				t.Fatal(err)
			}
			server.SetProfileProvider(provider)
			path, body := "/api/profiles", ""
			client.stallRead = method == "GET"
			client.stallSave = method == "PUT"
			if method == "PUT" {
				path += "/" + provider.order[0]
				body = `{"expected_revision":"` + fixture.response.Revision + `","profile":` + profileFixture + `}`
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			deadline, _ := ctx.Deadline()
			r := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
			w := httptest.NewRecorder()
			start := time.Now()
			server.Handler().ServeHTTP(w, r)
			if w.Code != 503 || time.Since(start) > time.Second || client.deadline.After(deadline) {
				t.Fatalf("deadline extended or response lost: %d %s deadline=%v", w.Code, w.Body, client.deadline)
			}
			if method == "PUT" && !strings.Contains(w.Body.String(), `"code":"indeterminate"`) {
				t.Fatalf("timed-out mutation was not uncertain: %s", w.Body)
			}
		})
	}
	if ProfileOperationTimeout+2*time.Second >= OperatorOperationTimeout {
		t.Fatal("helper cleanup leaves no operator transport headroom")
	}
}

func TestManagedAdapterConcurrentCAS(t *testing.T) {
	ctx := context.Background()
	client, ref := newManagedFixture(t)
	provider, err := NewManagedProfileProvider(ctx, client, []ManagedProfileRef{ref}, true)
	if err != nil {
		t.Fatal(err)
	}
	base, id := client.response.Revision, provider.order[0]
	results := make(chan error, 2)
	for _, path := range []string{"one", "two"} {
		go func(path string) {
			data := []byte(`{"version":1,"name":"default","files":[{"path":"` + path + `","access":["read"],"recursive":false}],"network":[]}`)
			_, _, err := provider.Replace(ctx, id, base, data)
			results <- err
		}(path)
	}
	first, second := <-results, <-results
	if (first == nil) == (second == nil) || first != nil && !errors.Is(first, config.ErrProfileConflict) || second != nil && !errors.Is(second, config.ErrProfileConflict) {
		t.Fatalf("concurrent CAS: %v; %v", first, second)
	}
}
