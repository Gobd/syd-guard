package syd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestTransparentWorkloadWaitsForNetworkReadyIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if runtime.GOOS != "linux" || engine == "" {
		t.Skip("requires Linux and explicit tested Syd")
	}
	work := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.MkdirTemp(home, ".sg-start-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(config) })
	t.Setenv("XDG_CONFIG_HOME", config)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ready := false
	code, err := Run(ctx, RunOptions{
		Engine: engine, Directory: work, Args: []string{"/bin/sh", "-c", "echo started > started"}, Scopes: []string{work}, TransitDNS: "10.232.1.1", Stdout: io.Discard, Stderr: io.Discard,
		OnReady: func(string, []string, []string) error { return nil },
		OnNetworkReady: func(socket string) error {
			if _, err := (IPC{Socket: socket}).Version(ctx); err != nil {
				return err
			}
			if _, err := os.Stat(filepath.Join(work, "started")); !os.IsNotExist(err) {
				return fmt.Errorf("workload started before network readiness")
			}
			time.Sleep(100 * time.Millisecond)
			ready = true
			return nil
		},
		OnEvent: func([]byte) error { return nil },
	})
	if err != nil || code != 0 || !ready {
		t.Fatalf("code=%d ready=%v err=%v", code, ready, err)
	}
	if _, err := os.Stat(filepath.Join(work, "started")); err != nil {
		t.Fatal(err)
	}
}
