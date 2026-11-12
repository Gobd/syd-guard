package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGoEligibilityIsCeilingOnlyAndRejectsProtectedOverlap(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	state := filepath.Join(root, "authority")
	cache := filepath.Join(root, "cache")
	bin := filepath.Join(root, "bin")
	for _, p := range []string{project, state, cache, bin} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fake := filepath.Join(bin, "go")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s' \"$FIXTURE_GO_ENV\"\n"), 0o700); err != nil { //nolint:gosec // private test executable fixture
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	data, _ := json.Marshal(map[string]string{"GOCACHE": cache})
	t.Setenv("FIXTURE_GO_ENV", string(data))
	roots, err := goEligibility(context.Background(), project, state)
	if err != nil || len(roots) != 1 {
		t.Fatalf("roots=%v err=%v", roots, err)
	}
	real, err := filepath.EvalSymlinks(cache)
	if err != nil || roots[0] != real {
		t.Fatalf("unexpected root %v %v", roots, err)
	}
	data, _ = json.Marshal(map[string]string{"GOCACHE": state})
	t.Setenv("FIXTURE_GO_ENV", string(data))
	realState, _ := filepath.EvalSymlinks(state)
	if _, err := goEligibility(context.Background(), project, realState); err == nil {
		t.Fatal("protected ceiling accepted")
	}
}
