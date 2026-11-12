package files

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedAndOutsideCeilings(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	protected := filepath.Join(root, "operator")
	if err := os.Mkdir(protected, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	manager := New()
	if err := manager.Register("run", "demo", Context{Socket: filepath.Join(protected, "syd.sock"), Scopes: []string{root}, Protected: []string{protected}}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(protected, "token"), filepath.Join(outside, "file"), filepath.Join(root, "escape", "file")} {
		manager.Observe("run", Event{Capability: "read", Action: "deny", Path: path})
	}
	values := manager.Pending()
	if len(values) != 1 || !values[0].RestartRequired || values[0].Attempts != 2 {
		t.Fatalf("outside denial must require restart; protected paths must remain hidden: %+v", values)
	}
	if err := manager.Decide(context.Background(), Decision{ID: values[0].ID, Action: "allow", Scope: "run"}); err == nil {
		t.Fatal("outside-ceiling request was approved")
	}
	manager.Observe("run", Event{Capability: "create", Action: "deny", Path: filepath.Join(root, "eligible")})
	values = manager.Pending()
	if len(values) != 2 {
		t.Fatal(values)
	}
	manager.End("run")
	if len(manager.Pending()) != 0 {
		t.Fatal("ended candidates retained")
	}
}

func TestProtectedPresetCannotBeApproved(t *testing.T) {
	root := t.TempDir()
	policy := filepath.Join(root, ".sydguard")
	if err := os.Mkdir(policy, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, ".env")
	if err := os.WriteFile(secret, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(secret, alias); err != nil {
		t.Fatal(err)
	}
	manager := New()
	if err := manager.Register("run", "fixture", Context{Socket: filepath.Join(root, "syd.sock"), Scopes: []string{root}, PolicyDirectory: policy}); err != nil {
		t.Fatal(err)
	}
	for _, event := range []Event{
		{Capability: "read", Action: "deny", Path: secret},
		{Capability: "stat", Action: "deny", Path: secret},
		{Capability: "read", Action: "deny", Path: alias},
		{Capability: "rename", Action: "deny", Path: root},
		{Capability: "write", Action: "deny", Path: filepath.Join(policy, "default.json")},
	} {
		manager.Observe("run", event)
	}
	if got := manager.Pending(); len(got) != 0 {
		t.Fatalf("protected requests exposed for approval: %+v", got)
	}
	if err := manager.Decide(context.Background(), Decision{ID: "forged", Action: "allow", Scope: "run"}); err == nil {
		t.Fatal("forged protected decision accepted")
	}
	manager.Observe("run", Event{Capability: "read", Action: "deny", Path: filepath.Join(policy, "default.json")})
	if len(manager.Pending()) != 1 {
		t.Fatal("policy intent should remain readable")
	}
}
