package guest

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/api"
	"github.com/Gobd/syd-guard/internal/policy"
)

func TestOutsideCeilingApprovalNotSaved(t *testing.T) {
	d, s := networkFixture(t)
	root, _ := filepath.EvalSymlinks(t.TempDir())
	s.Landlock = policy.Landlock{Enabled: true, Read: []string{root}, Write: []string{root}}
	outside := filepath.Join(t.TempDir(), "other")
	if _, err := d.allow(api.EditReq{Scope: "rules", File: s.RulesFile, Kind: "write", Pattern: outside}); err == nil || !strings.Contains(err.Error(), "Landlock ceiling") {
		t.Fatalf("outside grant: %v", err)
	}
	if got := d.store.Get(s.RulesFile); len(got.Write) != 0 {
		t.Fatal("unusable grant saved to rules")
	}
}

func TestTrustedChangeBeyondCeilingRequiresRestart(t *testing.T) {
	d, s := networkFixture(t)
	root, _ := filepath.EvalSymlinks(t.TempDir())
	s.Landlock = policy.Landlock{Enabled: true, Read: []string{root}}
	after := policy.Rules{Read: []string{filepath.Join(t.TempDir(), "other")}}
	result := d.applyChange(s.RulesFile, policy.Rules{}, after)
	if len(result) != 1 || result[0].Applied || s.Status != statusRestartRequired {
		t.Fatalf("result=%+v status=%q", result, s.Status)
	}
}
