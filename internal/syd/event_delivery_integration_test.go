package syd

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestTrustedEventDeliveryFailureStopsRunIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if runtime.GOOS != "linux" || engine == "" {
		t.Skip("requires Linux and explicit tested Syd")
	}
	work, scope := t.TempDir(), t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	secret := filepath.Join(scope, "input")
	if err := os.WriteFile(secret, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	_, err := Run(ctx, RunOptions{Engine: engine, Directory: work, Args: []string{"/bin/sh", "-c", "cat \"$1\"; sleep 20", "fixture", secret}, Scopes: []string{scope}, Stdout: io.Discard, Stderr: io.Discard, OnReady: func(string, []string, []string) error { return nil }, OnEvent: func([]byte) error { return errors.New("fixture delivery failure") }})
	if err == nil || !strings.Contains(err.Error(), "fixture delivery failure") {
		t.Fatalf("delivery failure lost: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("run was not stopped promptly")
	}
}
