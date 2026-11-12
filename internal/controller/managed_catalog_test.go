package controller

import (
	"bytes"
	"context"
	"errors"
	"strings"
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
	if f.beforeRead != nil {
		f.beforeRead()
		f.beforeRead = nil
	}
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
	client.beforeRead = func() {
		snapshot, err := config.ParseManagedProfileSnapshot("default", append(client.response.Profile, '\n'))
		if err != nil {
			t.Fatal(err)
		}
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
