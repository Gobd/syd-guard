//go:build linux

package learning

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/syd"
)

// This fixture exercises the actual Run bootstrap seam, not a hand-built profile.
// It requires the explicitly selected static upstream Syd and no privileges.
func TestBootstrapRunPermissionChecks(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if engine == "" {
		t.Skip("set SYDGUARD_TEST_SYD to the tested static Syd 3.59.0")
	}
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged execution")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{work, outside} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "config"))
	private := filepath.Join(base, "config", "sydguard")
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatal(err)
	}
	privateFile := filepath.Join(private, "operator-secret")
	if err := os.WriteFile(privateFile, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(outside, "input")
	if err := os.WriteFile(input, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outside, ".env")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	var collector *Collector
	var output bytes.Buffer
	code, runErr := syd.Run(context.Background(), syd.RunOptions{
		Engine: engine, Directory: work, Bootstrap: true,
		Args:   []string{"/bin/sh", "-c", `cat "$1" >/dev/null && printf data > "$2" && ! cat "$3" >/dev/null 2>&1 && ! cat "$4" >/dev/null 2>&1 && ! cat /proc/self/fd/3 >/dev/null 2>&1 && ! (printf forged >&3) 2>/dev/null && ! mv "$5" "$6" >/dev/null 2>&1`, "fixture", input, filepath.Join(outside, "created"), secret, privateFile, filepath.Join(base, "config"), filepath.Join(base, "moved-config")},
		Stdout: &output, Stderr: &output,
		OnBootstrapStart: func(temporary string, protected []string) error {
			var err error
			collector, err = New(Policy{Name: "bootstrap", Temporary: temporary, PolicyDirectory: filepath.Join(work, ".sydguard"), ExcludedRoots: protected, RateLimitDisabled: true})
			return err
		},
		OnTrustedLog: func(reader io.Reader) error { return collector.Drain(reader) },
	})
	if collector == nil {
		t.Fatalf("collector not initialized: code=%d err=%v output=%s", code, runErr, output.String())
	}
	collector.FinishOutcome(Outcome{ExitCode: code, Err: runErr})
	candidate := collector.Snapshot()
	if runErr != nil || code != 0 {
		t.Fatalf("run: code=%d err=%v output=%s candidate=%+v", code, runErr, output.String(), candidate)
	}
	if candidate.Incomplete || candidate.Kind != "permission-check-candidate" {
		t.Fatalf("unexpected candidate envelope: %+v", candidate)
	}
	checks := map[string]bool{}
	for _, rule := range candidate.Profile.Files {
		for _, access := range rule.Access {
			checks[rule.Path+":"+access] = true
		}
		if strings.Contains(rule.Path, ".env") {
			t.Fatal("secret path recorded")
		}
	}
	for _, key := range []string{input + ":read", filepath.Join(outside, "created") + ":write"} {
		if !checks[key] {
			t.Errorf("missing %s in %+v", key, candidate)
		}
	}
}

func TestBootstrapTrustedLogFailureStopsRun(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if engine == "" {
		t.Skip("set SYDGUARD_TEST_SYD to the tested static Syd 3.59.0")
	}
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged execution")
	}
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "config"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := syd.Run(ctx, syd.RunOptions{
		Engine: engine, Directory: base, Bootstrap: true,
		Args:             []string{"/bin/sleep", "30"},
		OnBootstrapStart: func(string, []string) error { return nil },
		OnTrustedLog:     func(io.Reader) error { return errors.New("deliberate log delivery failure") },
	})
	if err == nil || !strings.Contains(err.Error(), "trusted log delivery failed") || ctx.Err() != nil {
		t.Fatalf("log failure did not stop workload: err=%v ctx=%v", err, ctx.Err())
	}
}

// This is a parser/startup fixture only; it does not create a network namespace
// or establish a network connection, and cannot replace the parent gateway gate.
func TestBootstrapTransparentProfileStartupIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if engine == "" || os.Geteuid() == 0 {
		t.Skip("requires explicit unprivileged static Syd")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(home, ".sg-net-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(base) }()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "config"))
	work := filepath.Join(base, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	var collector *Collector
	var output bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ready := false
	code, err := syd.Run(ctx, syd.RunOptions{
		Engine: engine, Directory: work, Args: []string{"/bin/true"}, Bootstrap: true, TransitDNS: "10.232.0.1", Stdout: &output, Stderr: &output,
		OnBootstrapStart: func(temporary string, protected []string) error {
			var e error
			collector, e = New(Policy{Name: "test", Temporary: temporary, PolicyDirectory: filepath.Join(work, ".sydguard"), ExcludedRoots: protected, RateLimitDisabled: true})
			return e
		},
		OnTrustedLog:   func(reader io.Reader) error { return collector.Drain(reader) },
		OnNetworkReady: func(string) error { ready = true; return nil },
	})
	if err != nil || code != 0 || !ready || collector == nil {
		t.Fatalf("transparent startup code=%d ready=%t err=%v output=%s", code, ready, err, &output)
	}
	collector.FinishOutcome(Outcome{ExitCode: code})
	if collector.Snapshot().Incomplete {
		t.Fatalf("log delivery incomplete: %+v", collector.Snapshot())
	}
}
