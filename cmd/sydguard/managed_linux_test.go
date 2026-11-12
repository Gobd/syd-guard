//go:build linux

package main

import (
	"os"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/controller"
)

func TestManagedCredentialInitExclusivePrivate(t *testing.T) {
	_, _ = managedCommandTestSetup(t)
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		t.Skip("credential creation requires non-root")
	}
	state, err := controller.StateDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = managedRun([]string{"managed", "credential-init"}, ""); err == nil {
		t.Fatal("credential initialization without opt-in")
	}
	out, err := managedRun([]string{"managed", "--experimental", "credential-init"}, "")
	if err != nil {
		t.Fatal(err)
	}
	path := managedCredentialPath(state)
	data, err := os.ReadFile(path) //nolint:gosec // fixed credential under the test-owned private authority
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || len(data) != 64 || strings.Contains(out, string(data)) || strings.TrimSpace(out) != path {
		t.Fatal("credential is not private or leaked into output")
	}
	if _, err = managedRun([]string{"managed", "--experimental", "credential-init"}, ""); err == nil {
		t.Fatal("credential overwritten")
	}
	after, err := os.ReadFile(path) //nolint:gosec // fixed credential under the test-owned private authority
	if err != nil || string(after) != string(data) {
		t.Fatal("credential changed")
	}
}
