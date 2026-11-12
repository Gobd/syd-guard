package files

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/syd"
)

func TestTrustedLearningAndExactReadGrantIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if runtime.GOOS != "linux" || engine == "" {
		t.Skip("requires Linux and explicit tested Syd")
	}
	work, scope := t.TempDir(), t.TempDir()
	path := filepath.Join(scope, "reference")
	if err := os.WriteFile(path, []byte("approved-reference"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := New()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var output bytes.Buffer
	eventsSeen := 0
	done := make(chan error, 1)
	go func() {
		code, err := syd.Run(ctx, syd.RunOptions{Engine: engine, Directory: work, Args: []string{"/bin/sh", "-c", `set -eu
if printf FORGED_EVENT >&3; then exit 90; fi
while ! cat "$1" > result; do /bin/sleep 0.05; done
if printf overwrite > "$1"; then exit 91; fi
printf EXACT_READ_LEARNING_PASS
`, "fixture", path}, Scopes: []string{scope}, Stdout: &output, Stderr: &output, OnReady: func(socket string, scopes, protected []string) error {
			return manager.Register("run", "learning", Context{Socket: socket, Scopes: scopes, Protected: protected, PolicyDirectory: filepath.Join(work, ".sydguard")})
		}, OnEvent: func(data []byte) error {
			if eventsSeen < 8 {
				t.Logf("trusted event: %s", data)
			}
			eventsSeen++
			var event Event
			if json.Unmarshal(data, &event) == nil {
				manager.Observe("run", event)
			}
			return nil
		}})
		if err == nil && code != 0 {
			err = context.Canceled
		}
		done <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		requests := manager.Pending()
		var selected string
		for _, request := range requests {
			if request.Path == path && request.Capability == "read" {
				selected = request.ID
			}
		}
		if selected != "" {
			if err := manager.Decide(ctx, Decision{selected, "allow", "run"}); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			cancel()
			if err := <-done; err != nil {
				t.Logf("canceled fixture: %v", err)
			}
			t.Fatalf("no trusted read candidate: %+v output=%s", requests, &output)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := <-done; err != nil {
		t.Fatalf("learning fixture failed: %v %s", err, &output)
	}
	if !bytes.Contains(output.Bytes(), []byte("EXACT_READ_LEARNING_PASS")) {
		t.Fatal(output.String())
	}
	data, err := os.ReadFile(path) //nolint:gosec // test-owned reference path
	if err != nil || string(data) != "approved-reference" {
		t.Fatalf("read grant widened to write: %v %q", err, data)
	}
}
