package syd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDevelopmentGoCompatibilityIntegration(t *testing.T) {
	engine, tool := os.Getenv("SYDGUARD_TEST_SYD"), os.Getenv("SYDGUARD_TEST_NONPIE_GO")
	if runtime.GOOS != "linux" || engine == "" || tool == "" {
		t.Skip("requires explicit static Syd and known non-PIE Go fixture")
	}
	for _, requirePIE := range []bool{false, true} {
		t.Run(map[bool]string{false: "development", true: "require-pie"}[requirePIE], func(t *testing.T) {
			home, work := t.TempDir(), t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg"))
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			var output bytes.Buffer
			code, err := Run(ctx, RunOptions{Engine: engine, Directory: work, Args: []string{tool, "version"}, RequirePIE: requirePIE, Stdout: &output, Stderr: &output})
			if err != nil {
				t.Fatalf("Go compatibility execution: %v %s", err, &output)
			}
			if requirePIE {
				if code == 0 {
					t.Fatal("explicit PIE requirement accepted non-PIE fixture")
				}
			} else if code != 0 || !bytes.Contains(output.Bytes(), []byte("go version")) {
				t.Fatalf("standard Go runtime failed: code=%d output=%s", code, &output)
			}
		})
	}
}
