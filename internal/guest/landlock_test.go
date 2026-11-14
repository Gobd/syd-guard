package guest

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/api"
	"github.com/Gobd/syd-guard/internal/policy"
)

// An approval outside a session's ceiling is saved (new sessions with a wider
// ceiling use it), isn't applied to this session, is listed on it, and does
// not lock the session.
func TestOutsideCeilingApprovalSavedNotApplied(t *testing.T) {
	d, s := networkFixture(t)
	root, _ := filepath.EvalSymlinks(t.TempDir())
	s.Landlock = policy.Landlock{Enabled: true, Read: []string{root}, Write: []string{root}}
	outside := filepath.Join(t.TempDir(), "other")
	out, err := d.allow(api.EditReq{Scope: "rules", File: s.RulesFile, Kind: "write", Pattern: outside})
	if err != nil {
		t.Fatalf("outside grant refused: %v", err)
	}
	results := out.(map[string]any)["sessions"].([]applyResult)
	if len(results) != 1 || !strings.Contains(results[0].Note, "outside this session's Landlock ceiling") {
		t.Fatalf("results: %+v", results)
	}
	if got := d.store.Get(s.RulesFile); !slices.Contains(got.Write, outside) {
		t.Fatal("grant not saved")
	}
	if !slices.Contains(s.OutsideCeiling, "write "+outside) || s.Status == statusUnknown {
		t.Fatalf("outside=%v status=%q", s.OutsideCeiling, s.Status)
	}
}

func TestChangeBeyondCeilingDoesNotLockSession(t *testing.T) {
	_, s := networkFixture(t)
	root, _ := filepath.EvalSymlinks(t.TempDir())
	s.Landlock = policy.Landlock{Enabled: true, Read: []string{root}}
	other := filepath.Join(t.TempDir(), "other")
	after := policy.Rules{Read: []string{other}}
	if r := withinCeiling(s.Landlock, after); len(r.Read) != 0 {
		t.Fatalf("outside rule would reach Syd: %+v", r)
	}
	if got := outsideCeiling(s.Landlock, after); len(got) != 1 || got[0] != "read "+other {
		t.Fatalf("outsideCeiling = %v", got)
	}
	if got := outsideCeiling(policy.Landlock{}, after); got != nil {
		t.Fatalf("no ceiling should list nothing, got %v", got)
	}
}
