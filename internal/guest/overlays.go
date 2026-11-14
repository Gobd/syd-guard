package guest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Gobd/syd-guard/internal/api"
	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

// overlayDirs picks build/dependency folders to keep on the VM disk instead of
// the host-mounted project. Missing known folders are created empty.
func overlayDirs(project string, names []string) []string {
	var out []string
	add := func(rel string) {
		if strings.Contains(rel, ":") || len(out) >= 64 || slices.Contains(out, rel) {
			return
		}
		_ = os.MkdirAll(filepath.Join(project, rel), 0o755)
		out = append(out, rel)
	}
	exists := func(rel string) bool { _, err := os.Stat(filepath.Join(project, rel)); return err == nil }
	for _, n := range names {
		switch n {
		case ".venv":
			if exists("pyproject.toml") || exists("requirements.txt") || exists(".venv") {
				add(".venv")
			}
		case "target":
			if exists("Cargo.toml") {
				add("target")
			}
		case "node_modules":
			_ = filepath.WalkDir(project, func(p string, e os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				rel, _ := filepath.Rel(project, p)
				if e.IsDir() {
					if base := e.Name(); rel != "." && (base == "node_modules" || base == ".git" || strings.Count(rel, "/") >= 3) {
						return filepath.SkipDir
					}
					return nil
				}
				if e.Name() == "package.json" {
					add(filepath.Join(filepath.Dir(rel), "node_modules"))
				}
				return nil
			})
		default:
			if exists(n) {
				add(n)
			}
		}
	}
	return out
}

func overlayStore() string { return filepath.Join(system.Home(), ".cache", "sydguard", "overlay") }

// overlaySource is the VM-disk storage for one folder, keyed by its absolute
// path so every session (whichever project it started in) shares it.
func overlaySource(target string) string {
	dir := filepath.Join(overlayStore(), system.HashBytes([]byte(target))[:16])
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// overlayRoots are where keepOnVM folders are guarded: the host shares, or
// the project when there are none (plain Linux).
func overlayRoots(project string) []string {
	if shares := hostShares(); len(shares) > 0 {
		return shares
	}
	return []string{project}
}

// Saved overlays ------------------------------------------------------------

// Folders added live are remembered (outside the sandbox's reach) and mounted
// in every later session that can write them.
func savedOverlaysPath() string { return filepath.Join(system.StateDir(), "overlays.json") }

func savedOverlays() []string {
	var targets []string
	if data, err := os.ReadFile(savedOverlaysPath()); err == nil {
		_ = json.Unmarshal(data, &targets)
	}
	return targets
}

var savedMu sync.Mutex

func saveOverlay(target string) error {
	savedMu.Lock()
	defer savedMu.Unlock()
	targets := savedOverlays()
	if slices.Contains(targets, target) {
		return nil
	}
	data, _ := json.Marshal(append(targets, target))
	path := savedOverlaysPath()
	if err := os.WriteFile(path+".tmp", data, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// wantedOverlays: saved folders this session can write and guards.
func (d *Daemon) wantedOverlays(s *Session) []string {
	writes := []string{s.Project + "/***"}
	for _, r := range []policy.Rules{d.store.Get(system.GlobalRulesPath()), d.store.Get(s.RulesFile)} {
		writes = append(writes, withinCeiling(s.Landlock, r).Write...)
	}
	var out []string
	for _, t := range savedOverlays() {
		if policy.OverlayRoot(s.OverlayRoots, s.OverlayNames, t) == t && slices.ContainsFunc(writes, func(p string) bool { return policy.MatchPath(p, t) }) {
			out = append(out, t)
		}
	}
	return out
}

// prepareOverlayTarget creates the mount point on the share. It must be a real
// directory reached without symlinks, so the mount lands where asked.
func prepareOverlayTarget(target string) error {
	if fi, err := os.Lstat(target); err == nil && !fi.IsDir() {
		return fmt.Errorf("%s exists and is not a plain folder; remove it and retry", target)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(target); err != nil || real != target {
		return fmt.Errorf("%s goes through a symlink; overlay not added", target)
	}
	return nil
}

// Live overlays ---------------------------------------------------------------

// mountOverlay bind-mounts VM storage over a folder inside a running session's
// mount namespace. Called only from the session's update queue.
func (d *Daemon) mountOverlay(s *Session, target string) error {
	d.mu.Lock()
	done := slices.Contains(s.Overlays, target)
	d.mu.Unlock()
	if done {
		return nil
	}
	if s.SydPID <= 0 || !system.Alive(s.SydPID) {
		return errors.New("sandbox process unavailable; overlay not added")
	}
	if err := prepareOverlayTarget(target); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, sydguardExe(), "overlay-mount", strconv.Itoa(s.SydPID), overlaySource(target), target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount %s: %v: %s", target, err, strings.TrimSpace(string(out)))
	}
	if !mountedIn(s.SydPID, target) {
		return fmt.Errorf("mount %s: not visible in the sandbox", target)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	s.Overlays = append(s.Overlays, target)
	meta, _ := json.Marshal(s)
	return os.WriteFile(filepath.Join(sessionsDir(), s.ID+".json"), meta, 0o600)
}

// mountWanted mounts saved folders a session can now write (e.g. after a new
// grant), so an approved folder never needs asking twice. Best effort: a
// failure leaves the folder guarded and shows up as a card.
func (d *Daemon) mountWanted(s *Session) {
	for _, t := range d.wantedOverlays(s) {
		if err := d.mountOverlay(s, t); err != nil {
			log.Printf("session %s: saved overlay %s: %v", s.ID, t, err)
		}
	}
}

// addOverlay handles "Keep on VM" on a card: remember the folder and mount it
// into every running session that can write it.
func (d *Daemon) addOverlay(req api.EditReq) (any, error) {
	d.mu.Lock()
	var card *Card
	for _, c := range d.cards {
		if c.ID == req.Card && c.Overlay != "" {
			card = c
		}
	}
	var s *Session
	if card != nil {
		s = d.sessions[card.Session]
	}
	d.mu.Unlock()
	if s == nil {
		return nil, errors.New("this request is gone; retry the command to see it again")
	}
	target := card.Overlay
	// Mount where it was asked first; remember it only once that works.
	first := d.enqueue(s, applyOp{mount: target})
	if !first.Applied {
		return nil, fmt.Errorf("overlay not added: %s", first.Error)
	}
	if err := saveOverlay(target); err != nil {
		return nil, err
	}
	results := []applyResult{first}
	for _, o := range d.sessionsFor("") {
		if o != s && slices.Contains(d.wantedOverlays(o), target) {
			results = append(results, d.enqueue(o, applyOp{mount: target}))
		}
	}
	d.mu.Lock()
	for k, c := range d.cards {
		if o := d.sessions[c.Session]; o != nil && c.Kind == "write" && system.Under(c.Target, target) && slices.Contains(o.Overlays, target) {
			d.resolveLocked(k, true)
		}
	}
	d.mu.Unlock()
	return map[string]any{"sessions": results}, nil
}
