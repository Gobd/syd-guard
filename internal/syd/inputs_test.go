package syd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInputRulesAreExactReadOnlyAndProtected(t *testing.T) {
	dir := t.TempDir()
	config, executable := filepath.Join(dir, "harness.json"), filepath.Join(dir, "harness")
	for _, p := range []string{config, executable} {
		if err := os.WriteFile(p, []byte("fixture"), 0o700); err != nil { //nolint:gosec // private executable fixture
			t.Fatal(err)
		}
	}
	rules, err := InputRules([]string{config}, []string{executable}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"allow/write", "allow/create", "/***"} {
		if strings.Contains(rules, forbidden) {
			t.Fatalf("broad input rules: %s", rules)
		}
	}
	if _, err := InputRules([]string{config}, nil, []string{dir}); err == nil {
		t.Fatal("protected input accepted")
	}
	if _, err := InputRules([]string{dir}, nil, nil); err == nil {
		t.Fatal("directory input accepted")
	}
	if _, err := InputRules([]string{"relative"}, nil, nil); err == nil {
		t.Fatal("relative input accepted")
	}
}
