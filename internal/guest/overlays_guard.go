package guest

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

func (d *Daemon) concreteOverlayWrites(s *Session) []string {
	var writes []string
	for _, r := range []policy.Rules{d.store.Get(s.RulesFile), d.store.Get(system.GlobalRulesPath())} {
		writes = append(writes, withinCeiling(s.Landlock, r).Write...)
	}
	for _, b := range policy.Baseline(s.Project) {
		if b.Kind == "write" {
			writes = append(writes, b.Pattern)
		}
	}
	return writes
}

func (d *Daemon) overlayWrites(s *Session) []string {
	writes := d.concreteOverlayWrites(s)
	if s.Learn {
		writes = append(writes, "/***")
	}
	return writes
}

func (d *Daemon) overlayGuards(s *Session) ([]string, error) {
	if !s.OverlayGuarded {
		return nil, nil
	}
	d.mu.Lock()
	targets := slices.Clone(s.DynamicOverlays)
	readonly := slices.Clone(s.OverlayReadOnly)
	for _, rel := range s.Overlays {
		targets = append(targets, filepath.Join(s.Project, rel))
	}
	d.mu.Unlock()
	guards, err := policy.OverlayGuards(s.OverlayNames, targets, d.overlayWrites(s))
	if err != nil {
		return nil, err
	}
	reads := d.overlayReadRules(s)
	for _, root := range readonly {
		guards = append(guards, readOverlayCommands(root, reads)...)
	}
	return guards, nil
}

func (d *Daemon) automaticOverlay(s *Session, target, kind string) error {
	if fi, err := os.Lstat(target); kind == "read" && err == nil && fi.IsDir() &&
		!policy.OverlayWritable(target, d.concreteOverlayWrites(s)) && len(readOverlayCommands(target, d.overlayReadRules(s))) > 0 {
		result := d.enqueueUpdate(s, applyOp{readOverlay: target})
		if !result.Applied {
			return fmt.Errorf("%s", result.Error)
		}
		return nil
	}
	if filepath.Base(target) == "target" && !overlayPreviouslyRequested(target) {
		if fi, err := os.Stat(filepath.Join(filepath.Dir(target), "Cargo.toml")); err != nil || fi.IsDir() {
			return fmt.Errorf("%s is reserved by keepOnVM, but has no adjacent Cargo.toml; create the manifest and retry, click Create overlay, or remove target from keepOnVM and start a new session", target)
		}
	}
	result, err := d.requestOverlay(s, target)
	if err == nil && result.Exit != 0 {
		return fmt.Errorf("%s", result.Error)
	}
	return err
}

// The log reader never waits for a mount or IPC. Keep one attempt per target in
// flight; all privileged work and policy changes still go through the queue.
func (d *Daemon) queueAutomaticOverlayLocked(s *Session, target, kind string) {
	if s.Status == statusUnknown {
		return
	}
	for _, root := range s.DynamicOverlays {
		if system.Under(target, root) {
			return
		}
	}
	for _, rel := range s.Overlays {
		if system.Under(target, filepath.Join(s.Project, rel)) {
			return
		}
	}
	if s.pendingOverlays == nil {
		s.pendingOverlays = map[string]bool{}
	}
	if s.pendingOverlays[target] || len(s.pendingOverlays) >= 64 {
		return
	}
	s.pendingOverlays[target] = true
	go func() {
		err := d.automaticOverlay(s, target, kind)
		reads := d.overlayReadRules(s)
		d.mu.Lock()
		delete(s.pendingOverlays, target)
		for key, card := range d.cards {
			if card.Session != s.ID || (card.Kind != "read" && card.Kind != "write") || !system.Under(card.Target, target) {
				continue
			}
			switch {
			case err != nil:
				card.Note = "overlay not ready; access remains denied: " + err.Error()
			case slices.Contains(s.OverlayReadOnly, target) && card.Kind == "write":
				card.Note = "this toolchain was exposed read-only; start a new session with a write grant before overlaying it"
			case slices.Contains(s.OverlayReadOnly, target) && !slices.ContainsFunc(reads, func(p string) bool { return policy.MatchPath(p, card.Target) }):
				card.Note = "read-only toolchain: approve the requested read if needed"
			default:
				d.resolveLocked(key, true)
			}
		}
		d.mu.Unlock()
		d.events.Notify()
	}()
}
