//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLearnLimaPreservesNameAndPrintsGuestAuthority(t *testing.T) {
	base := t.TempDir()
	binary := filepath.Join(base, "limactl")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SYDGUARD_LIMA_CAPTURE\"\n"), 0o700); err != nil { //nolint:gosec // disposable executable test fixture
		t.Fatal(err)
	}
	capture := filepath.Join(base, "args")
	t.Setenv("PATH", base+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SYDGUARD_LIMA_CAPTURE", capture)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "config"))
	var out, stderr bytes.Buffer
	cmd := newCommand(&out, &stderr)
	err := cmd.Run(context.Background(), []string{"sydguard", "learn", "--backend", "lima", "--vm", "fixture", "--guest-sydguard", "/guest/syd'guard", "--guest-config-home", "/guest/conf space", "--directory", "/guest/project", "--syd", "/guest/syd", "--name", "agent-name", "--no-network", "--accept-experimental-risks", "--", "true"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(capture) //nolint:gosec // test-owned temporary file path
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "--name\nagent-name\n") || !strings.Contains(string(data), "XDG_CONFIG_HOME=/guest/conf space\n") {
		t.Fatalf("guest argv lost launch settings: %s", data)
	}
	instructions := stderr.String()
	for _, want := range []string{"Candidates and reviews are in the guest", "'XDG_CONFIG_HOME=/guest/conf space'", "'/guest/syd'\\''guard'", "'learn' 'show' 'CANDIDATE_ID'", "'learn' 'review-list'"} {
		if !strings.Contains(instructions, want) {
			t.Errorf("missing %q in %s", want, instructions)
		}
	}
}
