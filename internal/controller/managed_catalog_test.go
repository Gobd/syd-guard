package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/managedstore"
)

type catalogClientFixture struct {
	*managedClientFixture
	entries      []managedstore.CatalogEntry
	catalogError error
	catalogs     int
	deadline     time.Time
	beforeRead   func()
	readOnce     sync.Once
	stallCatalog bool
}

func (f *catalogClientFixture) Catalog(ctx context.Context) ([]managedstore.CatalogEntry, error) {
	f.catalogs++
	f.deadline, _ = ctx.Deadline()
	if f.stallCatalog {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.catalogError != nil {
		return nil, f.catalogError
	}
	if f.entries == nil {
		return nil, nil
	}
	entries := append([]managedstore.CatalogEntry{}, f.entries...)
	for i := range entries {
		if entries[i].Namespace != nil {
			namespace := *entries[i].Namespace
			entries[i].Namespace = &namespace
		}
	}
	return entries, nil
}

func (f *catalogClientFixture) Read(ctx context.Context, project, name string) (managedstore.Response, error) {
	f.readOnce.Do(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.beforeRead != nil {
			f.beforeRead()
		}
	})
	return f.managedClientFixture.Read(ctx, project, name)
}

func newCatalogFixture(t *testing.T) *catalogClientFixture {
	t.Helper()
	fixture, _ := newManagedFixture(t)
	namespace := *fixture.response.Namespace
	return &catalogClientFixture{managedClientFixture: fixture, entries: []managedstore.CatalogEntry{{
		Project: fixture.response.Project, Name: fixture.response.Name,
		Namespace: &namespace, Revision: fixture.response.Revision,
	}}}
}

func TestCatalogProviderAuthenticatesExactSnapshot(t *testing.T) {
	client := newCatalogFixture(t)
	provider, err := NewCatalogProfileProvider(context.Background(), client, false)
	if err != nil {
		t.Fatal(err)
	}
	if client.catalogs != 1 || client.reads != 1 || client.deadline.IsZero() || time.Until(client.deadline) > ProfileOperationTimeout {
		t.Fatal("catalog and exact snapshot must authenticate under a bounded construction budget")
	}
	list, err := provider.List(context.Background())
	if err != nil || len(list) != 1 || list[0].Edit {
		t.Fatalf("catalog-backed sources: %+v %v", list, err)
	}
	_, data, err := provider.ReadSnapshot(context.Background(), list[0].ID)
	if err != nil || !bytes.Equal(data, client.response.Profile) {
		t.Fatalf("exact snapshot: %s %v", data, err)
	}
	client.entries[0].Namespace.Path = "/forged"
	if provider.bindings[list[0].ID].namespace.Path == "/forged" {
		t.Fatal("catalog transport owns provider namespace")
	}
	if client.catalogs != 1 {
		t.Fatal("immutable provider silently re-enumerated authority")
	}
}

func TestCatalogProviderRejectsMalformedCatalogBeforeRead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*catalogClientFixture)
	}{
		{"null", func(f *catalogClientFixture) { f.entries = nil }},
		{"oversized", func(f *catalogClientFixture) { f.entries = make([]managedstore.CatalogEntry, 129) }},
		{"duplicate tuple", func(f *catalogClientFixture) { f.entries = append(f.entries, f.entries[0]) }},
		{"bad project ID", func(f *catalogClientFixture) { f.entries[0].Project = "/guessed-path" }},
		{"bad name", func(f *catalogClientFixture) { f.entries[0].Name = "../default" }},
		{"missing namespace", func(f *catalogClientFixture) { f.entries[0].Namespace = nil }},
		{"bad path", func(f *catalogClientFixture) { f.entries[0].Namespace.Path += "\t" }},
		{"cross-filesystem", func(f *catalogClientFixture) { f.entries[0].Namespace.PolicyDev++ }},
		{"bad revision", func(f *catalogClientFixture) { f.entries[0].Revision = "not-a-revision" }},
		{"mixed namespace", func(f *catalogClientFixture) {
			other := f.entries[0]
			other.Name = "build"
			namespace := *other.Namespace
			namespace.PolicyIno++
			other.Namespace = &namespace
			f.entries = append(f.entries, other)
		}},
		{"authentication failed", func(f *catalogClientFixture) { f.catalogError = errors.New("credential rejected") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newCatalogFixture(t)
			tc.mutate(client)
			if _, err := NewCatalogProfileProvider(context.Background(), client, true); err == nil {
				t.Fatal("invalid helper catalog became provider authority")
			}
			if client.reads != 0 || client.saves != 0 {
				t.Fatal("malformed catalog reached a snapshot/mutation operation")
			}
		})
	}
}

func TestCatalogProviderRejectsCrossRegistrationAliases(t *testing.T) {
	for _, alias := range []string{"path", "project inode", "policy inode"} {
		t.Run(alias, func(t *testing.T) {
			client := newCatalogFixture(t)
			other := client.entries[0]
			other.Project = strings.Repeat("b", 64)
			namespace := *other.Namespace
			namespace.Path = "/other"
			namespace.ProjectIno, namespace.PolicyIno = 20, 30
			switch alias {
			case "path":
				namespace.Path = client.entries[0].Namespace.Path
			case "project inode":
				namespace.ProjectIno = client.entries[0].Namespace.ProjectIno
			case "policy inode":
				namespace.PolicyIno = client.entries[0].Namespace.PolicyIno
			}
			other.Namespace = &namespace
			client.entries = append(client.entries, other)
			if _, err := NewCatalogProfileProvider(context.Background(), client, true); err == nil || client.reads != 0 {
				t.Fatal("aliased catalog reached snapshot authentication")
			}
		})
	}
}

func TestCatalogProviderRejectsChangedNamespaceDuringConstruction(t *testing.T) {
	client := newCatalogFixture(t)
	client.beforeRead = func() { client.response.Namespace.PolicyIno++ }
	if _, err := NewCatalogProfileProvider(context.Background(), client, true); err == nil {
		t.Fatal("namespace changed between catalog and exact snapshot")
	}
}

func TestCatalogProviderUsesFreshRevisionWithoutAutomaticReplay(t *testing.T) {
	client := newCatalogFixture(t)
	old := client.entries[0].Revision
	snapshot, err := config.ParseManagedProfileSnapshot("default", append(client.response.Profile, '\n'))
	if err != nil {
		t.Fatal(err)
	}
	client.beforeRead = func() {
		client.response.Profile, client.response.Revision = snapshot.Bytes(), snapshot.Revision()
	}
	provider, err := NewCatalogProfileProvider(context.Background(), client, false)
	if err != nil {
		t.Fatal(err)
	}
	list, err := provider.List(context.Background())
	if err != nil || len(list) != 1 || list[0].Edit {
		t.Fatalf("fresh unactivated source: %+v %v", list, err)
	}
	source, data, err := provider.ReadSnapshot(context.Background(), list[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	record, err := recordFromSource(source, data, false)
	if err != nil || record.Revision == old || record.Capabilities != (ProfileCapabilities{}) {
		t.Fatalf("catalog observations became reviewed/applied authority: %+v %v", record, err)
	}
}

func TestCatalogProviderEmptyAndCanceled(t *testing.T) {
	client := newCatalogFixture(t)
	client.entries = []managedstore.CatalogEntry{}
	provider, err := NewCatalogProfileProvider(context.Background(), client, true)
	if err != nil {
		t.Fatal(err)
	}
	list, err := provider.List(context.Background())
	if err != nil || list == nil || len(list) != 0 || client.reads != 0 {
		t.Fatalf("empty authenticated catalog: %+v %v", list, err)
	}
	if _, _, err := provider.ReadSnapshot(context.Background(), strings.Repeat("a", 64)); err == nil || client.reads != 0 {
		t.Fatal("empty catalog accepted a self-asserted profile ID")
	}
	client.stallCatalog = true
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := NewCatalogProfileProvider(ctx, client, false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled catalog escaped construction deadline: %v", err)
	}
}

type parallelCatalogFixture struct {
	mu           sync.Mutex
	entries      []managedstore.CatalogEntry
	responses    map[string]managedstore.Response
	catalogDelay time.Duration
	readDelay    time.Duration
	gate         <-chan struct{}
	failGate     <-chan struct{}
	started      chan string
	failName     string
	releaseName  string
	active       int
	maximum      int
	reads        int
	finished     int
}

func newParallelCatalogFixture(t *testing.T, count int) *parallelCatalogFixture {
	t.Helper()
	f := &parallelCatalogFixture{entries: make([]managedstore.CatalogEntry, 0, count), responses: make(map[string]managedstore.Response), started: make(chan string, count)}
	namespace := managedstore.ProjectNamespace{Path: "/registered-project", ProjectDev: 1, ProjectIno: 2, PolicyDev: 1, PolicyIno: 3}
	for i := range count {
		name := fmt.Sprintf("profile%03d", i)
		data := strings.Replace(profileFixture, `"name":"default"`, `"name":"`+name+`"`, 1)
		snapshot, err := config.ParseManagedProfileSnapshot(name, []byte(data))
		if err != nil {
			t.Fatal(err)
		}
		project := strings.Repeat("a", 64)
		f.entries = append(f.entries, managedstore.CatalogEntry{Project: project, Name: name, Namespace: &namespace, Revision: snapshot.Revision()})
		f.responses[name] = managedstore.Response{Project: project, Name: name, Namespace: &namespace, Profile: snapshot.Bytes(), Revision: snapshot.Revision()}
	}
	return f
}

func (f *parallelCatalogFixture) Catalog(ctx context.Context) ([]managedstore.CatalogEntry, error) {
	if err := waitFixture(ctx, f.catalogDelay, nil); err != nil {
		return nil, err
	}
	return f.entries, nil
}

func (f *parallelCatalogFixture) Read(ctx context.Context, project, name string) (managedstore.Response, error) {
	f.mu.Lock()
	f.active++
	f.reads++
	if f.active > f.maximum {
		f.maximum = f.active
	}
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.active--
		f.finished++
		f.mu.Unlock()
	}()
	select {
	case f.started <- name:
	default:
	}
	gate := f.gate
	if (name == f.failName || name == f.releaseName) && f.failGate != nil {
		gate = f.failGate
	}
	if err := waitFixture(ctx, f.readDelay, gate); err != nil {
		return managedstore.Response{}, err
	}
	if name == f.failName {
		return managedstore.Response{}, errors.New("snapshot authentication failed")
	}
	response, ok := f.responses[name]
	if !ok || response.Project != project {
		return managedstore.Response{}, errors.New("unknown registration")
	}
	return copyHelperResponse(response), nil
}

func (f *parallelCatalogFixture) Replace(context.Context, string, string, string, json.RawMessage) (managedstore.Response, error) {
	return managedstore.Response{}, errors.New("unexpected replace")
}

func waitFixture(ctx context.Context, delay time.Duration, gate <-chan struct{}) error {
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	if gate != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-gate:
		}
	}
	return ctx.Err()
}

func TestCatalogProviderParallelReadsUnderSharedDeadline(t *testing.T) {
	client := newParallelCatalogFixture(t, 2)
	client.catalogDelay, client.readDelay = 2*time.Second, 2*time.Second
	start := time.Now()
	provider, err := NewCatalogProfileProvider(context.Background(), client, true)
	elapsed := time.Since(start)
	if err != nil || elapsed >= ProfileOperationTimeout {
		t.Fatalf("parallel catalog construction took %v: %v", elapsed, err)
	}
	list, err := provider.List(context.Background())
	if err != nil || len(list) != 2 || list[0].Name != client.entries[0].Name || list[1].Name != client.entries[1].Name || !list[0].Edit || !list[1].Edit || client.maximum != 2 {
		t.Fatalf("ordered editable catalog: %+v, max=%d, err=%v", list, client.maximum, err)
	}
}

func TestCatalogProviderParallelReadBoundAndOrder(t *testing.T) {
	client := newParallelCatalogFixture(t, 128)
	gate := make(chan struct{})
	client.gate = gate
	type result struct {
		provider *ManagedProfileProvider
		err      error
	}
	done := make(chan result, 1)
	go func() {
		p, err := NewCatalogProfileProvider(context.Background(), client, true)
		done <- result{p, err}
	}()
	for range 4 {
		select {
		case <-client.started:
		case <-time.After(time.Second):
			close(gate)
			<-done
			t.Fatal("workers did not start")
		}
	}
	client.mu.Lock()
	active, maximum, reads := client.active, client.maximum, client.reads
	client.mu.Unlock()
	close(gate)
	r := <-done
	if r.err != nil || active != 4 || maximum != 4 || reads != 4 || client.maximum > 4 || client.finished != 128 {
		t.Fatalf("read bound: active=%d max=%d/%d started=%d finished=%d err=%v", active, maximum, client.maximum, reads, client.finished, r.err)
	}
	list, err := r.provider.List(context.Background())
	if err != nil || len(list) != len(client.entries) {
		t.Fatalf("incomplete catalog: %d %v", len(list), err)
	}
	for i, source := range list {
		if source.Name != client.entries[i].Name || !source.Edit {
			t.Fatalf("catalog order/capability at %d: %+v", i, source)
		}
	}
}

func TestCatalogProviderParallelCancellationJoinsWorkers(t *testing.T) {
	client := newParallelCatalogFixture(t, 8)
	client.gate = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		provider *ManagedProfileProvider
		err      error
	}
	done := make(chan result, 1)
	go func() { p, err := NewCatalogProfileProvider(ctx, client, true); done <- result{p, err} }()
	for range 4 {
		select {
		case <-client.started:
		case <-time.After(time.Second):
			cancel()
			<-done
			t.Fatal("workers did not start")
		}
	}
	cancel()
	select {
	case r := <-done:
		if r.provider != nil || !errors.Is(r.err, context.Canceled) || client.active != 0 || client.reads != 4 || client.finished != 4 {
			t.Fatalf("cancellation leaked work or published provider: %+v active=%d reads=%d finished=%d", r, client.active, client.reads, client.finished)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled workers did not join")
	}
}

func TestCatalogProviderParallelFailureRejectsEntireCatalog(t *testing.T) {
	for _, kind := range []string{"read failure", "malformed snapshot", "changed namespace"} {
		t.Run(kind, func(t *testing.T) {
			client := newParallelCatalogFixture(t, 2)
			name := client.entries[1].Name
			switch kind {
			case "read failure":
				client.failName = name
			case "malformed snapshot":
				response := client.responses[name]
				response.Revision = strings.Repeat("0", 64)
				client.responses[name] = response
			case "changed namespace":
				response := client.responses[name]
				namespace := *response.Namespace
				namespace.PolicyIno++
				response.Namespace = &namespace
				client.responses[name] = response
			}
			provider, err := NewCatalogProfileProvider(context.Background(), client, true)
			if err == nil || provider != nil || client.active != 0 || client.reads != client.finished {
				t.Fatalf("failure published partial catalog or leaked workers: %v %v", provider, err)
			}
		})
	}
}

func TestCatalogProviderParallelFailureCancelsStalledWorkers(t *testing.T) {
	client := newParallelCatalogFixture(t, 8)
	client.gate = make(chan struct{})
	failGate := make(chan struct{})
	client.failGate, client.failName = failGate, client.entries[0].Name
	type result struct {
		provider *ManagedProfileProvider
		err      error
	}
	done := make(chan result, 1)
	go func() {
		p, err := NewCatalogProfileProvider(context.Background(), client, true)
		done <- result{p, err}
	}()
	for range 4 {
		select {
		case <-client.started:
		case <-time.After(time.Second):
			close(failGate)
			<-done
			t.Fatal("workers did not start")
		}
	}
	close(failGate)
	select {
	case r := <-done:
		if r.provider != nil || r.err == nil || r.err.Error() != "snapshot authentication failed" || client.active != 0 || client.reads != 4 || client.finished != 4 {
			t.Fatalf("failure did not cancel and join workers: %+v active=%d reads=%d finished=%d", r, client.active, client.reads, client.finished)
		}
	case <-time.After(time.Second):
		t.Fatal("failed read did not cancel stalled workers")
	}
}

func TestCatalogProviderNamespaceMismatchCancelsStalledWorker(t *testing.T) {
	client := newParallelCatalogFixture(t, 2)
	client.gate = make(chan struct{})
	release := make(chan struct{})
	client.failGate, client.releaseName = release, client.entries[0].Name
	response := client.responses[client.releaseName]
	namespace := *response.Namespace
	namespace.PolicyIno++
	response.Namespace = &namespace
	client.responses[client.releaseName] = response
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		provider *ManagedProfileProvider
		err      error
	}
	done := make(chan result, 1)
	go func() {
		p, err := NewCatalogProfileProvider(ctx, client, true)
		done <- result{p, err}
	}()
	for range 2 {
		select {
		case <-client.started:
		case <-time.After(time.Second):
			cancel()
			<-done
			t.Fatal("workers did not start")
		}
	}
	close(release)
	select {
	case r := <-done:
		if r.provider != nil || r.err == nil || r.err.Error() != "managed namespace changed between catalog and snapshot" || client.active != 0 || client.reads != 2 || client.finished != 2 {
			t.Fatalf("namespace mismatch did not cancel and join worker: %+v active=%d reads=%d finished=%d", r, client.active, client.reads, client.finished)
		}
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("namespace mismatch did not promptly cancel stalled worker")
	}
}

func TestCatalogProviderParallelStallsRespectDeadline(t *testing.T) {
	client := newParallelCatalogFixture(t, 2)
	client.gate = make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	provider, err := NewCatalogProfileProvider(ctx, client, true)
	if provider != nil || !errors.Is(err, context.DeadlineExceeded) || client.active != 0 || client.reads != 2 || client.finished != 2 {
		t.Fatalf("stalled reads exceeded deadline or leaked: %v %v active=%d reads=%d finished=%d", provider, err, client.active, client.reads, client.finished)
	}
}

func TestCatalogProviderTwoProfilesEditableBeforeSession(t *testing.T) {
	client := newParallelCatalogFixture(t, 2)
	entry := &client.entries[1]
	entry.Project = strings.Repeat("b", 64)
	namespace := managedstore.ProjectNamespace{Path: "/other-registered-project", ProjectDev: 1, ProjectIno: 20, PolicyDev: 1, PolicyIno: 30}
	entry.Namespace = &namespace
	response := client.responses[entry.Name]
	response.Project, response.Namespace = entry.Project, &namespace
	client.responses[entry.Name] = response
	provider, err := NewCatalogProfileProvider(context.Background(), client, true)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	server.SetProfileProvider(provider)
	w := profileRequest(server.Handler(), "GET", "/api/profiles", "", true)
	var records []ProfileMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &records); err != nil || w.Code != 200 || len(records) != 2 {
		t.Fatalf("pre-session profile API: %d %s %v", w.Code, w.Body, err)
	}
	for i, record := range records {
		if record.Name != client.entries[i].Name || !record.Capabilities.Edit || record.Capabilities.Reload || record.Capabilities.SavedDecisions {
			t.Fatalf("pre-session profile capability: %+v", record)
		}
		w := profileRequest(server.Handler(), "GET", "/api/profiles/"+record.ID, "", true)
		if w.Code != 200 {
			t.Fatalf("pre-session profile read: %d %s", w.Code, w.Body)
		}
	}
}
