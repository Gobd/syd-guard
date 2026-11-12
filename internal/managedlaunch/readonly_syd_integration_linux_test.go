//go:build linux

package managedlaunch_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/managedlaunch"
	"github.com/Gobd/syd-guard/internal/syd"
)

// This is an ordinary-UID static Syd fixture, not a privileged mount test.
func TestReadOnlyProfileStaticSydIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if engine == "" {
		t.Skip("requires explicit static Syd 3.59.0")
	}
	home, project, scratch, public := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.Chmod(scratch, 0o700); err != nil { //nolint:gosec // fixture scratch directory must be private and traversable
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	if err := os.WriteFile(filepath.Join(project, "visible"), []byte("reviewed-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"version":1,"name":"default","files":[{"path":".","access":["read"],"recursive":true}],"network":[]}`)
	snapshot, err := config.ParseManagedProfileSnapshot("default", data)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := managedlaunch.SelectedProfile(snapshot, project)
	if err != nil {
		t.Fatal(err)
	}
	selected := filepath.Join(public, "selected.json")
	if err := os.WriteFile(selected, data, 0o444); err != nil { //nolint:gosec // fixture models public read-only intent
		t.Fatal(err)
	}
	t.Setenv("SYDGUARD_SELECTED_PROFILE", selected)
	t.Setenv("SYDGUARD_PROFILE_NAME", "default")
	t.Setenv("SYDGUARD_PROJECT_ID", "fixture-project")
	t.Setenv("SYDGUARD_PROFILE_REVISION", snapshot.Revision())
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			_ = conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var output bytes.Buffer
	code, err := syd.Run(ctx, syd.RunOptions{
		Engine: engine, Directory: project, ResolvedProfile: &resolved, WorkTemporaryRoot: scratch,
		Args:   []string{"/bin/sh", "-c", `set -eu; [ "$SYDGUARD_SELECTED_PROFILE" = "$1" ]; [ "$SYDGUARD_PROFILE_NAME" = default ]; [ "$SYDGUARD_PROJECT_ID" = fixture-project ]; [ "$SYDGUARD_PROFILE_REVISION" = "$3" ]; printf scratch > "$SYDGUARD_TMPDIR/test"; [ -n "$(cat "$SYDGUARD_SELECTED_PROFILE")" ]; cat visible; cat "$1"; if printf denied > visible; then exit 91; fi; if /bin/sh -c 'printf forge >&3'; then exit 93; fi; /usr/bin/curl --version; if /usr/bin/curl --noproxy "*" --connect-timeout 2 --max-time 3 -s "$2"; then exit 92; fi`, "fixture", selected, fmt.Sprintf("http://%s", listener.Addr()), snapshot.Revision()},
		Stdout: &output, Stderr: &output, StrictInputs: syd.TrustedRuntimeInputs{Read: []string{selected}}, OnStrictRuntimeCapabilities: func(syd.StrictRuntimeCapabilities) error { return nil },
	})
	if err != nil || code != 0 {
		t.Fatalf("strict run code=%d err=%v output=%s", code, err, output.String())
	}
	if !strings.Contains(output.String(), `"cap":"net/connect"`) {
		t.Fatalf("missing actual network denial: %s", output.String())
	}
	got, err := os.ReadFile(filepath.Join(project, "visible")) //nolint:gosec // fixture-owned path
	if err != nil || string(got) != "reviewed-data" {
		t.Fatalf("project changed: %q %v", got, err)
	}
}
