package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/controller"
	"github.com/Gobd/syd-guard/internal/managedstore"
)

type managedCommandFixture struct {
	calls    []string
	response managedstore.Response
	expected string
	data     []byte
	failure  error
}

func (f *managedCommandFixture) Register(_ context.Context, p string) (string, error) {
	f.calls = append(f.calls, "register:"+p)
	return strings.Repeat("a", 64), f.failure
}

func (f *managedCommandFixture) Create(_ context.Context, p, n string) (managedstore.Response, error) {
	f.calls = append(f.calls, "create:"+p+":"+n)
	return f.response, f.failure
}

func (f *managedCommandFixture) Catalog(context.Context) ([]managedstore.CatalogEntry, error) {
	f.calls = append(f.calls, "catalog")
	return []managedstore.CatalogEntry{}, f.failure
}

func (f *managedCommandFixture) Read(_ context.Context, p, n string) (managedstore.Response, error) {
	f.calls = append(f.calls, "read:"+p+":"+n)
	return f.response, f.failure
}

func (f *managedCommandFixture) Replace(_ context.Context, p, n, r string, data json.RawMessage) (managedstore.Response, error) {
	f.calls = append(f.calls, "replace:"+p+":"+n)
	f.expected = r
	f.data = append([]byte(nil), data...)
	return f.response, f.failure
}

func managedCommandTestSetup(t *testing.T) (*managedCommandFixture, string) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(home, ".sg-managed-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	t.Setenv("XDG_CONFIG_HOME", root)
	t.Setenv("HOME", root)
	state, err := controller.StateDirectory()
	if err != nil {
		t.Fatal(err)
	}
	fixture := &managedCommandFixture{response: managedstore.Response{Project: strings.Repeat("a", 64), Name: "default", Revision: strings.Repeat("b", 64), Profile: []byte(`{"version":1,"name":"default","files":[],"network":[]}`)}}
	oldOpen, oldPlatform := managedOpen, managedCheckPlatform
	managedCheckPlatform = func() error { return nil }
	managedOpen = func(path string) (managedClient, error) {
		if path != managedCredentialPath(state) {
			t.Fatalf("wrong credential path %s", path)
		}
		return fixture, nil
	}
	t.Cleanup(func() { managedOpen, managedCheckPlatform = oldOpen, oldPlatform })
	return fixture, root
}

func managedRun(args []string, input string) (string, error) {
	var out bytes.Buffer
	cmd := newCommand(&out, &out)
	cmd.Reader = strings.NewReader(input)
	err := cmd.Run(context.Background(), append([]string{"sydguard"}, args...))
	return out.String(), err
}

func TestManagedCommandOptInAndCAS(t *testing.T) {
	f, _ := managedCommandTestSetup(t)
	if _, err := managedRun([]string{"managed", "catalog"}, ""); err == nil || len(f.calls) != 0 {
		t.Fatal("catalog lacked explicit opt-in")
	}
	if _, err := managedRun([]string{"managed", "--experimental", "save", "--project-id", "id", "--expected-revision", "rev"}, "{}"); err == nil || len(f.calls) != 0 {
		t.Fatal("save lacked explicit confirmation")
	}
	out, err := managedRun([]string{"managed", "--experimental", "catalog"}, "")
	if err != nil || !strings.Contains(out, "[]") {
		t.Fatalf("catalog: %q %v", out, err)
	}
	input := `{"version":1,"name":"default","files":[],"network":[]}`
	out, err = managedRun([]string{"managed", "--experimental", "save", "--project-id", "id", "--expected-revision", "rev", "--yes"}, input)
	if err != nil || f.expected != "rev" || string(f.data) != input || !strings.Contains(out, `"profile":{"version":1`) {
		t.Fatalf("save: %q %v %+v", out, err, f)
	}
	f.failure = managedstore.ErrConflict
	if _, err = managedRun([]string{"managed", "--experimental", "save", "--project-id", "id", "--expected-revision", "rev", "--yes"}, input); !errors.Is(err, managedstore.ErrConflict) {
		t.Fatalf("conflict lost: %v", err)
	}
}

func TestManagedCreateShowAndIndeterminateSave(t *testing.T) {
	f, root := managedCommandTestSetup(t)
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := managedRun([]string{"managed", "--experimental", "register", "--directory", project, "--yes"}, "")
	if err != nil || strings.TrimSpace(out) != strings.Repeat("a", 64) {
		t.Fatalf("registration: %q %v", out, err)
	}
	out, err = managedRun([]string{"managed", "--experimental", "create", "--project-id", "id", "--name", "default", "--yes"}, "")
	if err != nil || !strings.Contains(out, `"revision":`) {
		t.Fatalf("create: %q %v", out, err)
	}
	out, err = managedRun([]string{"managed", "--experimental", "show", "--project-id", "id"}, "")
	if err != nil || !strings.Contains(out, `"profile":`) {
		t.Fatalf("show: %q %v", out, err)
	}
	f.failure = managedstore.ErrIndeterminate
	if _, err = managedRun([]string{"managed", "--experimental", "save", "--project-id", "id", "--expected-revision", "rev", "--yes"}, `{}`); !errors.Is(err, managedstore.ErrIndeterminate) {
		t.Fatalf("indeterminate outcome lost: %v", err)
	}
}

func TestManagedRegisterRejectsAuthorityOverlap(t *testing.T) {
	f, root := managedCommandTestSetup(t)
	_, err := managedRun([]string{"managed", "--experimental", "register", "--directory", root, "--yes"}, "")
	if err == nil || len(f.calls) != 0 {
		t.Fatal("registered authority ancestor")
	}
}

type failedManagedOutput struct{ err error }

func (w failedManagedOutput) Write([]byte) (int, error) { return 0, w.err }

func TestManagedCommittedMutationOutputFailure(t *testing.T) {
	fixture, root := managedCommandTestSetup(t)
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	outputError := errors.New("test output full")
	for _, args := range [][]string{
		{"register", "--directory", project, "--yes"},
		{"create", "--project-id", "id", "--yes"},
		{"save", "--project-id", "id", "--expected-revision", "rev", "--yes"},
	} {
		fixture.calls = nil
		cmd := newCommand(failedManagedOutput{outputError}, io.Discard)
		cmd.Reader = strings.NewReader(`{"version":1,"name":"default","files":[],"network":[]}`)
		err := cmd.Run(context.Background(), append([]string{"sydguard", "managed", "--experimental"}, args...))
		if !errors.Is(err, managedstore.ErrIndeterminate) || !errors.Is(err, outputError) || len(fixture.calls) != 1 {
			t.Fatalf("post-commit output failure: %v calls=%v", err, fixture.calls)
		}
	}
}

func TestManagedBrokenStdoutSubprocess(t *testing.T) {
	if os.Getenv("SYDGUARD_TEST_MANAGED_PIPE") == "1" {
		managedCheckPlatform = func() error { return nil }
		fixture := &managedCommandFixture{response: managedstore.Response{Project: strings.Repeat("a", 64), Name: "default", Revision: strings.Repeat("b", 64), Profile: []byte(`{"version":1,"name":"default","files":[],"network":[]}`)}}
		managedOpen = func(string) (managedClient, error) { return fixture, nil }
		cmd := newCommand(os.Stdout, os.Stderr)
		err := cmd.Run(context.Background(), []string{"sydguard", "managed", "--experimental", "create", "--project-id", "id", "--yes"})
		if !errors.Is(err, managedstore.ErrIndeterminate) || len(fixture.calls) != 1 {
			os.Exit(7)
		}
		_, _ = fmt.Fprintln(os.Stderr, "COMMITTED_RECONCILE_REQUIRED")
		os.Exit(0)
	}
	_, _ = managedCommandTestSetup(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = write.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestManagedBrokenStdoutSubprocess$") //nolint:gosec // current test executable and fixed subprocess fixture
	cmd.Env = append(os.Environ(), "SYDGUARD_TEST_MANAGED_PIPE=1")
	cmd.Stdout = write
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil || !strings.Contains(stderr.String(), "COMMITTED_RECONCILE_REQUIRED") {
		t.Fatalf("SIGPIPE lost post-commit guidance: %v stderr=%s", err, &stderr)
	}
}

func TestManagedUnavailablePlatformFailsClosed(t *testing.T) {
	f, _ := managedCommandTestSetup(t)
	managedCheckPlatform = func() error { return errors.New("unsupported") }
	if _, err := managedRun([]string{"managed", "--experimental", "catalog"}, ""); err == nil || len(f.calls) != 0 {
		t.Fatal("unsupported platform contacted helper")
	}
}
