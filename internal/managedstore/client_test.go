//go:build linux || darwin

package managedstore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/config"
)

func TestRegisterRejectsOriginalInvalidPathBeforeTransport(t *testing.T) {
	// A nil client proves this rejection cannot reach credential/transport code.
	// JSON would otherwise replace the invalid byte with U+FFFD.
	var client *Client
	path := "/project" + string([]byte{0xff})
	id, err := client.Register(context.Background(), path)
	if err == nil || id != "" || errors.Is(err, ErrIndeterminate) {
		t.Fatalf("invalid original path reached registration: %q %v", id, err)
	}
}

func TestCreateCredential(t *testing.T) {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		t.Skip("client requires an unprivileged user")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // directory access requires execute permission
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credential")
	if err := CreateCredential(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 64 {
		t.Fatalf("credential length = %d", len(data))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("credential mode = %v", info.Mode())
	}
	if err := CreateCredential(path); err == nil {
		t.Fatal("overwrote credential")
	}
	if err := os.Link(path, path+"-alias"); err != nil {
		t.Fatal(err)
	}
	c := &Client{credentialFile: path}
	if _, err := c.credential(); err == nil {
		t.Fatal("accepted a credential with multiple links")
	}
}

func TestCreateCredentialRejectsUnprivateDirectory(t *testing.T) {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		t.Skip("client requires an unprivileged user")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // deliberate insecure-directory test
		t.Fatal(err)
	}
	if err := CreateCredential(filepath.Join(dir, "credential")); err == nil {
		t.Fatal("accepted non-private directory")
	}
}

func TestCredentialFailureIsNotSubmitted(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // private test directory requires owner search
		t.Fatal(err)
	}
	c := &Client{credentialFile: filepath.Join(dir, "missing")}
	if _, err := c.Replace(context.Background(), strings.Repeat("a", 64), "test", strings.Repeat("b", 64), []byte(`{}`)); !errors.Is(err, ErrNotSubmitted) || errors.Is(err, ErrIndeterminate) {
		t.Fatalf("credential preflight error: %v", err)
	}
}

func TestMutationCancellationBeforeStartIsNotSubmitted(t *testing.T) {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		t.Skip("client requires an unprivileged user")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // private directory needs owner search permission
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credential")
	if err := CreateCredential(path); err != nil {
		t.Fatal(err)
	}
	c := &Client{credentialFile: path}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Create(ctx, "registration", "test"); !errors.Is(err, ErrNotSubmitted) || errors.Is(err, ErrIndeterminate) {
		t.Fatalf("mutation error = %v", err)
	}
	if _, err := c.Read(ctx, "registration", "test"); errors.Is(err, ErrIndeterminate) || err == nil {
		t.Fatalf("read error = %v", err)
	}
	if !errors.Is(&ClientError{Code: "indeterminate", Message: "uncertain"}, ErrIndeterminate) {
		t.Fatal("server indeterminate not typed")
	}
	if !errors.Is(&ClientError{Code: "409", Message: "conflict"}, ErrConflict) || errors.Is(&ClientError{Code: "indeterminate"}, ErrConflict) {
		t.Fatal("conflict typing incorrect")
	}
}

func TestProcessHelperResponseBindingAndConflict(t *testing.T) {
	id := strings.Repeat("a", 64)
	data := []byte(`{"version":1,"name":"test","files":[],"network":[]}`)
	snapshot, err := config.ParseManagedProfileSnapshot("test", data)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Operation: "replace", Project: id, Name: "test", Profile: data}
	response := Response{Project: id, Name: "test", Profile: data, Revision: snapshot.Revision(), Namespace: &ProjectNamespace{Path: "/project", ProjectIno: 2, PolicyIno: 3}}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := processHelperResponse(request, boundedBuffer{data: encoded}, nil, false); err != nil {
		t.Fatalf("valid response: %v", err)
	}
	response.Project = strings.Repeat("b", 64)
	encoded, err = json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := processHelperResponse(request, boundedBuffer{data: encoded}, nil, false); !errors.Is(err, ErrIndeterminate) {
		t.Fatalf("mismatched replacement must be indeterminate: %v", err)
	}
	request.Operation = "read"
	if _, err := processHelperResponse(request, boundedBuffer{data: encoded}, nil, false); err == nil || errors.Is(err, ErrIndeterminate) {
		t.Fatalf("mismatched read: %v", err)
	}
	conflict := boundedBuffer{data: []byte(`{"error":"conflict","code":"409"}`)}
	request.Operation = "replace"
	if _, err := processHelperResponse(request, conflict, errors.New("helper exit"), false); !errors.Is(err, ErrConflict) {
		t.Fatalf("replace conflict: %v", err)
	}
	request.Operation = "create"
	if _, err := processHelperResponse(request, conflict, errors.New("helper exit"), false); !errors.Is(err, ErrIndeterminate) || errors.Is(err, ErrConflict) {
		t.Fatalf("unexpected create conflict: %v", err)
	}
}

func TestValidateResponseSnapshotBinding(t *testing.T) {
	id := strings.Repeat("a", 64)
	data := []byte(`{ "version":1,"name":"test","files":[],"network":[]}`)
	snapshot, err := config.ParseManagedProfileSnapshot("test", data)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Operation: "read", Project: id, Name: "test"}
	response := Response{Project: id, Name: "test", Revision: snapshot.Revision(), Profile: data, Namespace: &ProjectNamespace{Path: "/project", ProjectDev: 1, ProjectIno: 2, PolicyDev: 1, PolicyIno: 3}}
	validated, err := validateResponse(request, response)
	if err != nil || string(validated.Profile) != string(data) {
		t.Fatalf("valid exact snapshot: %v", err)
	}
	response.Profile[0] = '['
	if validated.Profile[0] != '{' {
		t.Fatal("snapshot bytes are not defensively copied")
	}
	response.Profile = data
	response.Profile[0] = '{'
	for name, mutate := range map[string]func(*Response){
		"wrong project":     func(r *Response) { r.Project = strings.Repeat("b", 64) },
		"invalid id":        func(r *Response) { r.Project = strings.Repeat("A", 64) },
		"wrong name":        func(r *Response) { r.Name = "other" },
		"missing namespace": func(r *Response) { r.Namespace = nil },
		"relative path":     func(r *Response) { r.Namespace = &ProjectNamespace{Path: "project"} },
		"unclean path":      func(r *Response) { r.Namespace = &ProjectNamespace{Path: "/project/../other"} },
		"control path":      func(r *Response) { r.Namespace = &ProjectNamespace{Path: "/project\nother"} },
		"wrong revision":    func(r *Response) { r.Revision = strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := response
			mutate(&bad)
			if _, err := validateResponse(request, bad); err == nil {
				t.Fatal("accepted mismatched response")
			}
		})
	}
	request.Operation = "replace"
	request.Profile = []byte(`{"version":1,"name":"test","files":[],"network":[]}`)
	if _, err := validateResponse(request, response); err == nil {
		t.Fatal("accepted replacement with different exact bytes")
	}
	request.Profile = data
	if _, err := validateResponse(request, response); err != nil {
		t.Fatalf("valid replacement: %v", err)
	}
	if _, err := validateResponse(Request{Operation: "register"}, Response{Project: "/project"}); err == nil {
		t.Fatal("accepted pathname as registration ID")
	}
}
