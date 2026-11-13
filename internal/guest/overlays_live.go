package guest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

const maxLiveOverlays = 256

func (d *Daemon) requestOverlay(s *Session, path string) (CmdResult, error) {
	if err := d.checkOverlayRequest(s, path); err != nil {
		return CmdResult{}, err
	}
	result := d.enqueueUpdate(s, applyOp{overlay: path})
	if !result.Applied {
		return CmdResult{Exit: 1, Error: result.Error}, nil
	}
	d.mu.Lock()
	for key, card := range d.cards {
		if card.Session == s.ID && (card.Kind == "read" || card.Kind == "write") && system.Under(card.Target, path) {
			d.resolveLocked(key, true)
		}
	}
	d.mu.Unlock()
	d.events.Notify()
	return CmdResult{Stdout: "overlay ready: " + path + " (existing contents hidden; retry the denied operation)\n"}, nil
}

// AddOverlay is the operator-side command on the execution machine. Agents use
// their session-scoped SG_BROKER endpoint instead, never the daemon socket.
func AddOverlay(session, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	var result CmdResult
	if err := Call("POST", "/api/overlay", map[string]string{"Session": session, "Path": abs}, &result); err != nil {
		return err
	}
	if result.Exit != 0 {
		return errors.New(result.Error)
	}
	fmt.Print(result.Stdout)
	return nil
}

func dynamicOverlayRoot() string { return filepath.Join(system.StateDir(), "overlays") }

func overlayPreviouslyRequested(target string) bool {
	fi, err := os.Lstat(filepath.Join(dynamicOverlayRoot(), system.HashBytes([]byte(target))))
	return err == nil && fi.IsDir()
}

// Discover only beneath the literal grant prefix, plus its ancestors (to catch
// a grant to a file within target/). No symlink traversal. Bounds fail visibly,
// rather than granting writes after silently skipping part of a large tree.
func discoverWriteOverlays(pattern string, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	root := policy.LiteralPrefix(pattern)
	if system.SafePath(root) != nil {
		return nil, fmt.Errorf("cannot scan write grant %q", pattern)
	}
	if root == "/" {
		return nil, errors.New("write grant too broad for overlay discovery; grant a project directory instead")
	}
	var out []string
	seen := map[string]bool{}
	exists := func(p string) bool { _, err := os.Lstat(p); return err == nil }
	inspect := func(dir string) error {
		for _, name := range names {
			if !policy.ValidOverlayName(name) {
				return fmt.Errorf("invalid overlay name %q", name)
			}
			target := filepath.Join(dir, name)
			if seen[target] || !policy.Overlaps(pattern, target) {
				continue
			}
			fi, statErr := os.Lstat(target)
			if statErr != nil && !os.IsNotExist(statErr) {
				return statErr
			}
			if fi != nil && !fi.IsDir() {
				return fmt.Errorf("reserved overlay path must be a real directory, not a symlink/file: %s", target)
			}
			wanted := fi != nil
			switch name {
			case "target":
				if !exists(filepath.Join(dir, "Cargo.toml")) && !overlayPreviouslyRequested(target) {
					if wanted {
						return fmt.Errorf("reserved target folder lacks Cargo.toml: %s; remove target from keepOnVM to use it as an ordinary folder", target)
					}
					continue
				}
				wanted = true
			case "node_modules":
				wanted = wanted || exists(filepath.Join(dir, "package.json"))
			case ".venv":
				wanted = wanted || exists(filepath.Join(dir, "pyproject.toml")) || exists(filepath.Join(dir, "requirements.txt"))
			}
			if wanted {
				seen[target] = true
				out = append(out, target)
				if len(out) > maxLiveOverlays {
					return errors.New("too many build folders for one live write grant")
				}
			}
		}
		return nil
	}
	for dir := root; dir != "/"; dir = filepath.Dir(dir) {
		if err := inspect(dir); err != nil {
			return nil, err
		}
	}
	count := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		count++
		if count > 20000 {
			return errors.New("write-grant scan exceeds 20000 entries; grant a smaller directory")
		}
		if !entry.IsDir() {
			return nil
		}
		if entry.Name() == ".git" || slices.Contains(names, entry.Name()) {
			return filepath.SkipDir
		}
		return inspect(path)
	})
	slices.Sort(out)
	return out, err
}

// Include saved write grants at startup too: a restart must not bypass a
// failed live-overlay check, and siblings approved last run need their mounts.
func initializeOverlays(s *Session, rules []policy.Rules) error {
	patterns := []string{s.Project + "/***"}
	for _, r := range rules {
		patterns = append(patterns, withinCeiling(s.Landlock, r).Write...)
	}
	seen := map[string]bool{}
	s.Overlays, s.DynamicOverlays, s.OverlayReadOnly = nil, nil, nil
	for _, path := range s.Launch {
		root := policy.OverlayTarget(s.OverlayNames, path)
		if root != "" && !policy.OverlayWritable(root, patterns) && !slices.Contains(s.OverlayReadOnly, root) {
			s.OverlayReadOnly = append(s.OverlayReadOnly, root)
		}
	}
	for _, pattern := range patterns {
		targets, err := discoverWriteOverlays(pattern, s.OverlayNames)
		if err != nil {
			return err
		}
		for _, target := range targets {
			if seen[target] {
				continue
			}
			seen[target] = true
			if len(seen) > maxLiveOverlays {
				return errors.New("too many build folders for this session")
			}
			if err := policy.ProtectedFor(s.Project, s.RulesFile, system.GlobalRulesPath()).Check("write", target+"/***"); err != nil {
				return err
			}
			if err := ensureOverlayDir(target, true); err != nil {
				return err
			}
			if system.Under(target, s.Project) {
				rel, _ := filepath.Rel(s.Project, target)
				s.Overlays = append(s.Overlays, rel)
			} else {
				s.DynamicOverlays = append(s.DynamicOverlays, target)
			}
		}
	}
	return nil
}

// Called only by the session's update queue, before Syd receives new writes.
func (d *Daemon) prepareWriteOverlays(s *Session, lines []string) error {
	if len(s.OverlayNames) > 0 && !s.OverlayGuarded {
		return errors.New("this session predates deny-first overlays; start a new session")
	}
	prefix := "allow/" + policy.WriteCaps + "+"
	for _, line := range lines {
		if pattern, ok := strings.CutPrefix(line, prefix); ok {
			targets, err := discoverWriteOverlays(pattern, s.OverlayNames)
			if err != nil {
				return err
			}
			for _, target := range targets {
				if err := d.installOverlay(s, target); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Explicit requests cannot grant filesystem access, choose a source, or mount
// over arbitrary folders: only configured basenames in already-writable paths.
func (d *Daemon) checkOverlayRequest(s *Session, target string) error {
	if !s.OverlayGuarded {
		return errors.New("this session predates deny-first overlays; start a new session")
	}
	if system.SafePath(target) != nil || strings.ContainsAny(target, "*?[]{}\\") || filepath.Clean(target) != target || !slices.Contains(s.OverlayNames, filepath.Base(target)) {
		return errors.New("overlay path must be an absolute directory with a configured keepOnVM name")
	}
	prot := policy.ProtectedFor(s.Project, s.RulesFile, system.GlobalRulesPath())
	if err := prot.Check("write", target+"/***"); err != nil {
		return err
	}
	if err := s.Landlock.Check("write", target); err != nil {
		return err
	}
	if policy.OverlayWritable(target, d.overlayWrites(s)) {
		return nil
	}
	return errors.New("approve a literal recursive write grant for this directory or its parent before adding an overlay")
}

func (d *Daemon) installOverlay(s *Session, target string) error {
	if err := policy.ProtectedFor(s.Project, s.RulesFile, system.GlobalRulesPath()).Check("write", target+"/***"); err != nil {
		return err
	}
	d.mu.Lock()
	for _, root := range s.OverlayReadOnly {
		if system.Under(target, root) || system.Under(root, target) {
			d.mu.Unlock()
			return errors.New("this build-folder tree was already exposed read-only; start a new session with its write grant to avoid stale directory handles")
		}
	}
	startupRel := ""
	for _, rel := range s.Overlays {
		if filepath.Join(s.Project, rel) == target {
			startupRel = rel
			break
		}
	}
	known := startupRel != "" || slices.Contains(s.DynamicOverlays, target)
	pid := s.SydPID
	count := len(s.DynamicOverlays) + len(s.Overlays)
	d.mu.Unlock()
	if !known && count >= maxLiveOverlays {
		return errors.New("session overlay limit reached; start a new session")
	}
	if pid <= 0 || !system.Alive(pid) {
		return errors.New("sandbox process unavailable; overlay not installed")
	}
	source := filepath.Join(dynamicOverlayRoot(), system.HashBytes([]byte(target)))
	if startupRel != "" {
		source = overlaySource(s.Project, startupRel)
	}
	// Older sessions did not reserve overlay storage in their Landlock ceiling.
	if err := s.Landlock.Check("write", source); err != nil {
		return fmt.Errorf("dynamic overlay storage exceeds Landlock ceiling; start a new session: %w", err)
	}
	if !known {
		if err := os.MkdirAll(source, 0o700); err != nil {
			return err
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !known {
		// Freeze the target pathname BEFORE creating/mounting it. The broad
		// build-folder guard still denies handles/access throughout this phase.
		locks := append(policy.OverlayPathLocks(target), policy.ProtectedFor(s.Project, s.RulesFile, system.GlobalRulesPath()).Commands()...)
		if err := sydLoad(s, locks); err != nil {
			return fmt.Errorf("cannot lock overlay path before mount: %w", err)
		}
	}
	args := []string{"overlay-mount", fmt.Sprint(pid), source, target}
	if known {
		args = append(args, "check")
	}
	out, err := exec.CommandContext(ctx, exe, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("overlay %s failed; write update withheld: %w: %s", target, err, strings.TrimSpace(string(out)))
	}
	if known {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	s.DynamicOverlays = append(s.DynamicOverlays, target)
	meta, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(sessionsDir(), s.ID+".json"), meta, 0o600); err != nil {
		return fmt.Errorf("overlay mounted but metadata save failed: %w", err)
	}
	return nil
}
