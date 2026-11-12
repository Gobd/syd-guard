package syd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectedPathPreset(t *testing.T) {
	policy := "/repo/.sydguard"
	for _, p := range []string{"/repo/.env", "/repo/a/foo.env", "/repo/a/b/.env.local", "/repo/.ssh/id", "/repo/.netrc", "/home/u/.config/google-chrome/Default/Login Data"} {
		if !ProtectedPath(p, "read", policy) {
			t.Errorf("read allowed: %s", p)
		}
	}
	for _, p := range []string{"/repo/.sydguard", "/repo/.sydguard/default.json", "/repo"} {
		if !ProtectedPath(p, "rename", policy) {
			t.Errorf("rename allowed: %s", p)
		}
	}
	if ProtectedPath("/repo/.sydguard/default.json", "read", policy) || ProtectedPath("/home/u/.config/tool/config", "read", policy) {
		t.Fatal("non-secret readable intent blocked")
	}
}

func TestProtectedRulesAndInputs(t *testing.T) {
	work := t.TempDir()
	rules, err := ProtectedRules(work, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"deny/all+/.env", "deny/all+/**/.env", "deny/all+/**/*.env", "deny/all+/**/.env.*/***", "deny/delete,rename,rmdir+"} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %s", want)
		}
	}
	secret := filepath.Join(work, ".env")
	if err := os.WriteFile(secret, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(work, "alias")
	if err := os.Symlink(secret, alias); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{secret, alias} {
		if _, err := InputRules([]string{input}, nil, nil); err == nil {
			t.Fatalf("protected input accepted: %s", input)
		}
	}
	if err := os.Symlink(work, filepath.Join(work, ".sydguard")); err != nil {
		t.Fatal(err)
	}
	if _, err := ProtectedRules(work, nil); err == nil {
		t.Fatal("symlink policy directory accepted")
	}
}
