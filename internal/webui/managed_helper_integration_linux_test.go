//go:build linux

package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/controller"
	"github.com/Gobd/syd-guard/internal/managedstore"
)

// The barrier lets a separate real helper writer commit after the controller's
// preflight read, but before its real helper replacement; no store is simulated.
type helperCASBarrier struct {
	*managedstore.Client
	mu    sync.Mutex
	start chan struct{}
	done  chan error
}

func (c *helperCASBarrier) Replace(ctx context.Context, project, name, revision string, data json.RawMessage) (managedstore.Response, error) {
	c.mu.Lock()
	start, done := c.start, c.done
	c.start, c.done = nil, nil
	c.mu.Unlock()
	if start != nil {
		close(start)
		select {
		case err := <-done:
			if err != nil {
				return managedstore.Response{}, fmt.Errorf("concurrent helper writer: %w", err)
			}
		case <-ctx.Done():
			return managedstore.Response{}, ctx.Err()
		}
	}
	return c.Client.Replace(ctx, project, name, revision, data)
}

// Requires administrator attestation that the installed immutable helper and
// fixed registry are disposable, plus a freshly enrolled test credential. The
// caller profile catalog must be empty; that check does not prove the registry
// lacks other UIDs or empty registrations. Never run as root.
func TestManagedHelperProfileBridgeIntegration(t *testing.T) {
	if os.Getenv("SYDGUARD_MANAGED_UI_INTEGRATION") != "1" {
		t.Skip("requires disposable installed-helper fixture")
	}
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		t.Fatal("fixture must run as an ordinary user")
	}
	credential := os.Getenv("SYDGUARD_HELPER_CREDENTIAL")
	if !filepath.IsAbs(credential) || filepath.Clean(credential) != credential {
		t.Fatal("SYDGUARD_HELPER_CREDENTIAL must be an absolute clean private credential path")
	}
	client, err := managedstore.NewClient(credential)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx := context.Background()
	catalog, err := client.Catalog(ctx)
	if err != nil || catalog == nil || len(catalog) != 0 {
		t.Fatalf("fixture requires an empty caller profile catalog: entries=%d err=%v", len(catalog), err)
	}
	dir, err := os.MkdirTemp("", "sydguard-managed-ui-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("administrator cleanup required for test directory and fixed registry: %s", dir)
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	projects := [2]string{filepath.Join(dir, "project-a"), filepath.Join(dir, "project-b")}
	var ids [2]string
	var created [2]managedstore.Response
	for i, project := range projects {
		if err := os.Mkdir(project, 0o700); err != nil {
			t.Fatal(err)
		}
		ids[i], err = client.Register(ctx, project)
		if err != nil {
			t.Fatalf("register project %d: %v", i, err)
		}
		created[i], err = client.Create(ctx, ids[i], "default")
		if err != nil {
			t.Fatalf("create profile %d: %v", i, err)
		}
	}
	if ids[0] == ids[1] || ids[0] == projects[0] || ids[1] == projects[1] {
		t.Fatal("project registration IDs are not distinct opaque IDs")
	}
	catalog, err = client.Catalog(ctx)
	if err != nil || len(catalog) != 2 {
		t.Fatalf("catalog: entries=%d err=%v", len(catalog), err)
	}
	for i := range ids {
		found := false
		for _, entry := range catalog {
			if entry.Project == ids[i] && entry.Name == "default" && entry.Revision == created[i].Revision && entry.Namespace != nil && created[i].Namespace != nil && *entry.Namespace == *created[i].Namespace {
				found = true
			}
		}
		if !found {
			t.Fatalf("catalog omitted exact registration %d", i)
		}
	}
	barrier := &helperCASBarrier{Client: client}
	provider, err := controller.NewCatalogProfileProvider(ctx, barrier, true)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := provider.List(ctx)
	if err != nil || len(sources) != 2 {
		t.Fatalf("provider list: %v", err)
	}
	var profileIDs [2]string
	for _, source := range sources {
		for i := range projects {
			if source.Project == projects[i] {
				profileIDs[i] = source.ID
				_, snapshot, readErr := provider.ReadSnapshot(ctx, source.ID)
				if readErr != nil || !bytes.Equal(snapshot, created[i].Profile) {
					t.Fatalf("provider exact snapshot %d: %v", i, readErr)
				}
			}
		}
	}
	if profileIDs[0] == "" || profileIDs[1] == "" || profileIDs[0] == profileIDs[1] || profileIDs[0] == ids[0] || profileIDs[1] == ids[1] {
		t.Fatal("profile identities are not distinct opaque bindings")
	}

	const master = "managed-ui-test-controller-master-token"
	const uiToken = "managed-ui-test-operator-access-token"
	server, err := controller.New(master)
	if err != nil {
		t.Fatal(err)
	}
	server.SetProfileProvider(provider)
	backend := httptest.NewServer(server.Handler())
	defer backend.Close()
	bridge := httptest.NewUnstartedServer(nil)
	bridge.Config.Handler = Handler(bridge.Listener.Addr().String(), uiToken, func(ctx context.Context, method, path string, data []byte) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, method, backend.URL+path, bytes.NewReader(data)) //nolint:gosec // loopback test server and webui's allowlisted route
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+master)
		resp, err := backend.Client().Do(req) //nolint:gosec // loopback test server
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 400 {
			return nil, &controller.OperatorError{Status: resp.StatusCode, Body: body}
		}
		return body, nil
	})
	bridge.Start()
	defer bridge.Close()
	request := func(method, path, body, token string) (int, []byte) {
		t.Helper()
		req, reqErr := http.NewRequestWithContext(ctx, method, bridge.URL+path, strings.NewReader(body)) //nolint:gosec // loopback test server and fixture-owned routes
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, reqErr := bridge.Client().Do(req) //nolint:gosec // loopback fixture server
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		defer func() { _ = resp.Body.Close() }()
		data, reqErr := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		return resp.StatusCode, data
	}
	path := "/api/profiles/" + profileIDs[0]
	status, body := request("GET", "/api/profiles", "", "wrong")
	if status != http.StatusUnauthorized {
		t.Fatalf("UI authentication: %d %s", status, body)
	}
	status, body = request("GET", "/api/profiles", "", uiToken)
	var list []controller.ProfileMetadata
	if err := json.Unmarshal(body, &list); err != nil || status != http.StatusOK || len(list) != 2 {
		t.Fatalf("UI catalog: %d %s %v", status, body, err)
	}
	for i := range profileIDs {
		found := false
		for _, item := range list {
			if item.ID == profileIDs[i] && item.Project == projects[i] && item.Revision == created[i].Revision && item.Capabilities.Edit && !item.Capabilities.Reload && !item.Capabilities.SavedDecisions {
				found = true
			}
		}
		if !found {
			t.Fatalf("UI metadata missing binding/capabilities %d", i)
		}
	}
	status, body = request("GET", path, "", uiToken)
	var record controller.ProfileRecord
	var expectedProfile config.Profile
	if err := json.Unmarshal(created[0].Profile, &expectedProfile); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &record); err != nil || status != http.StatusOK || record.Revision != created[0].Revision || !reflect.DeepEqual(record.Profile, expectedProfile) {
		t.Fatalf("UI read: %d %s %v", status, body, err)
	}
	const desired = `{ "version":1,"name":"default","files":[{"path":"src","access":["read"],"recursive":false}],"network":[] }`
	save := func(revision, profile string) string {
		return `{"expected_revision":"` + revision + `","profile":` + profile + `}`
	}
	status, body = request("PUT", path, save(record.Revision, desired), uiToken)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"applied":false`)) || !bytes.Contains(body, []byte("running permissions are unchanged")) {
		t.Fatalf("UI save: %d %s", status, body)
	}
	saved, err := client.Read(ctx, ids[0], "default")
	if err != nil || !bytes.Equal(saved.Profile, []byte(desired)) {
		t.Fatalf("saved helper exact bytes: %v", err)
	}
	other, err := client.Read(ctx, ids[1], "default")
	if err != nil || other.Revision != created[1].Revision || !bytes.Equal(other.Profile, created[1].Profile) {
		t.Fatalf("other project changed: %v", err)
	}
	status, body = request("GET", path, "", uiToken)
	var savedRecord controller.ProfileRecord
	if err := json.Unmarshal(saved.Profile, &expectedProfile); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &savedRecord); err != nil || status != http.StatusOK || savedRecord.Revision != saved.Revision || !reflect.DeepEqual(savedRecord.Profile, expectedProfile) {
		t.Fatalf("saved UI read: %d %s %v", status, body, err)
	}
	status, body = request("GET", "/api/profiles/"+profileIDs[1], "", uiToken)
	if err := json.Unmarshal(created[1].Profile, &expectedProfile); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &savedRecord); err != nil || status != http.StatusOK || savedRecord.Revision != created[1].Revision || !reflect.DeepEqual(savedRecord.Profile, expectedProfile) {
		t.Fatalf("other UI profile: %d %s %v", status, body, err)
	}
	status, body = request("PUT", path, save(record.Revision, desired), uiToken)
	if status != http.StatusConflict || !bytes.Contains(body, []byte(`"code":"revision_conflict"`)) || !bytes.Contains(body, []byte(saved.Revision)) {
		t.Fatalf("dirty stale draft conflict: %d %s", status, body)
	}
	status, body = request("PUT", path, save(saved.Revision, `{"version":1,"name":"default","files":[],"network":[],"bad":true}`), uiToken)
	if status != http.StatusUnprocessableEntity || !bytes.Contains(body, []byte(`"code":"invalid_profile"`)) {
		t.Fatalf("invalid profile error transport: %d %s", status, body)
	}
	status, body = request("GET", "/api/profiles/"+ids[0], "", uiToken)
	if status != http.StatusNotFound {
		t.Fatalf("registration ID used as profile authority: %d %s", status, body)
	}
	status, body = request("GET", "/api/profiles"+projects[0], "", uiToken)
	if status != http.StatusNotFound {
		t.Fatalf("project path used as profile authority: %d %s", status, body)
	}
	status, body = request("POST", path+"/reload", `{}`, uiToken)
	if status != http.StatusNotImplemented || !bytes.Contains(body, []byte(`"code":"unsupported"`)) || !bytes.Contains(body, []byte("running permissions are unchanged")) {
		t.Fatalf("reload: %d %s", status, body)
	}

	const concurrent = `{"version":1,"name":"default","files":[{"path":"other","access":["write"],"recursive":false}],"network":[]}`
	const draft = `{"version":1,"name":"default","files":[{"path":"draft","access":["read"],"recursive":false}],"network":[]}`
	start, done := make(chan struct{}), make(chan error, 1)
	barrier.mu.Lock()
	barrier.start, barrier.done = start, done
	barrier.mu.Unlock()
	go func() {
		select {
		case <-start:
			writerCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, writerErr := client.Replace(writerCtx, ids[0], "default", saved.Revision, json.RawMessage(concurrent))
			done <- writerErr
		case <-time.After(10 * time.Second):
		}
	}()
	status, body = request("PUT", path, save(saved.Revision, draft), uiToken)
	current, err := client.Read(ctx, ids[0], "default")
	if err != nil || !bytes.Equal(current.Profile, []byte(concurrent)) {
		t.Fatalf("concurrent helper result: %v", err)
	}
	if status != http.StatusConflict || !bytes.Contains(body, []byte(`"code":"revision_conflict"`)) || !bytes.Contains(body, []byte(current.Revision)) {
		t.Fatalf("helper CAS conflict through UI: %d %s", status, body)
	}
	if _, err := client.Replace(ctx, ids[0], "default", saved.Revision, json.RawMessage(draft)); !errors.Is(err, managedstore.ErrConflict) {
		t.Fatalf("actual helper stale CAS: %v", err)
	}
	status, body = request("GET", path, "", uiToken)
	if err := json.Unmarshal(current.Profile, &expectedProfile); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &record); err != nil || status != http.StatusOK || record.Revision != current.Revision || !reflect.DeepEqual(record.Profile, expectedProfile) {
		t.Fatalf("UI reconciliation: %d %s %v", status, body, err)
	}
	other, err = client.Read(ctx, ids[1], "default")
	if err != nil || other.Revision != created[1].Revision || !bytes.Equal(other.Profile, created[1].Profile) {
		t.Fatalf("concurrent update crossed project identity: %v", err)
	}

	// Rename only our own project entry to provoke a real helper namespace error.
	// Restore it even on failure; these observations do not pin a namespace.
	policy := filepath.Join(projects[0], ".sydguard")
	moved := filepath.Join(projects[0], "policy-moved")
	if err := os.Rename(policy, moved); err != nil {
		t.Fatal(err)
	}
	restored := false
	t.Cleanup(func() {
		if !restored {
			if err := os.Rename(moved, policy); err != nil {
				t.Errorf("restore test policy namespace: %v", err)
			}
		}
	})
	status, body = request("GET", "/api/profiles", "", uiToken)
	if status != http.StatusServiceUnavailable || !bytes.Contains(body, []byte(`"code":"unavailable"`)) {
		t.Fatalf("helper namespace error through UI: %d %s", status, body)
	}
	if err := os.Rename(moved, policy); err != nil {
		t.Fatal(err)
	}
	restored = true
	status, body = request("GET", path, "", uiToken)
	if err := json.Unmarshal(body, &record); err != nil || status != http.StatusOK || record.Revision != current.Revision {
		t.Fatalf("restored helper read: %d %s %v", status, body, err)
	}
}
