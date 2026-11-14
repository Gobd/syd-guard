package guest

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Gobd/syd-guard/internal/api"
	"github.com/Gobd/syd-guard/internal/policy"
)

func testDaemon(t *testing.T) *Daemon {
	t.Setenv("HOME", t.TempDir())
	if err := os.MkdirAll(sessionsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	return &Daemon{sessions: map[string]*Session{}, cards: map[string]*Card{}, store: policy.NewStore(), events: api.NewBroadcaster()}
}

// Saved folders follow write access, not the project a session started in.
func TestWantedOverlaysFollowWriteGrants(t *testing.T) {
	d := testDaemon(t)
	for _, target := range []string{"/share/p/web/node_modules", "/share/y/node_modules", "/share/y/node_modules", "/share/z/src", "/vm/node_modules"} {
		if err := saveOverlay(target); err != nil {
			t.Fatal(err)
		}
	}
	if got := savedOverlays(); len(got) != 4 {
		t.Fatalf("duplicates must collapse: %v", got)
	}
	rules := filepath.Join(t.TempDir(), ".sydguard.json")
	s := &Session{Project: "/share/p", RulesFile: rules, OverlayRoots: []string{"/share"}, OverlayNames: []string{"node_modules"}}
	if got := d.wantedOverlays(s); !slices.Equal(got, []string{"/share/p/web/node_modules"}) {
		t.Fatalf("before grant: %v", got)
	}
	if _, _, err := d.store.Edit(rules, policy.AddRule("write", "/share/y/***")); err != nil {
		t.Fatal(err)
	}
	if got := d.wantedOverlays(s); !slices.Equal(got, []string{"/share/p/web/node_modules", "/share/y/node_modules"}) {
		t.Fatalf("after sibling grant: %v", got)
	}
}

func TestPrepareOverlayTargetRefusesSymlinks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareOverlayTarget(filepath.Join(root, "web/node_modules")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "lib")); err != nil {
		t.Fatal(err)
	}
	if err := prepareOverlayTarget(filepath.Join(root, "lib/node_modules")); err == nil {
		t.Fatal("followed a symlinked parent")
	}
	if err := os.WriteFile(filepath.Join(root, "target"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareOverlayTarget(filepath.Join(root, "target")); err == nil {
		t.Fatal("accepted a file as mount point")
	}
}

// Denied writes inside a guarded folder anywhere on the share collapse into one
// "Keep on VM" card per folder; mounted folders get ordinary cards.
func TestGuardedWriteBecomesOverlayCard(t *testing.T) {
	d := testDaemon(t)
	s := &Session{
		ID: "s1", Project: "/share/p", RulesFile: "/share/p/.sydguard.json", OverlayRoots: []string{"/share"},
		OverlayNames: []string{"node_modules"}, Overlays: []string{"/share/p/node_modules"},
	}
	d.sessions[s.ID] = s
	d.syslog(s.ID, []string{
		`{"ctx":"access","cap":"mkdir","act":"deny","path":"/share/y/node_modules","cmd":"npm i"}`,
		`{"ctx":"access","cap":"write","act":"deny","path":"/share/y/node_modules/a/index.js","cmd":"npm i"}`,
		`{"ctx":"access","cap":"write","act":"deny","path":"/share/p/node_modules/a/index.js","cmd":"npm i"}`,
	})
	var overlay, plain []*Card
	for _, c := range d.cards {
		if c.Overlay != "" {
			overlay = append(overlay, c)
		} else {
			plain = append(plain, c)
		}
	}
	if len(overlay) != 1 || overlay[0].Overlay != "/share/y/node_modules" || overlay[0].Count != 2 || len(overlay[0].Options) != 0 {
		t.Fatalf("overlay cards: %+v", overlay)
	}
	if len(plain) != 1 || plain[0].Target != "/share/p/node_modules/a/index.js" {
		t.Fatalf("plain cards: %+v", plain)
	}
}

// A failed mount must not mark the session's policy state unknown (nothing
// reached Syd), and a folder is only remembered once it mounted.
func TestFailedMountKeepsSessionUsable(t *testing.T) {
	d := testDaemon(t)
	s := &Session{
		ID: "s1", Project: "/share/p", RulesFile: "/share/p/.sydguard.json", Status: statusApplied,
		OverlayRoots: []string{"/share"}, OverlayNames: []string{"node_modules"},
	}
	d.sessions[s.ID] = s
	d.startQueue(s)
	d.syslog(s.ID, []string{`{"ctx":"access","cap":"mkdir","act":"deny","path":"/share/p/node_modules","cmd":"npm i"}`})
	var card string
	for _, c := range d.cards {
		card = c.ID
	}
	if _, err := d.addOverlay(api.EditReq{Card: card}); err == nil {
		t.Fatal("mount without a sandbox process succeeded")
	}
	if s.Status != statusApplied {
		t.Fatalf("status = %s after a failed mount", s.Status)
	}
	if got := savedOverlays(); len(got) != 0 {
		t.Fatalf("failed folder was saved: %v", got)
	}
}
