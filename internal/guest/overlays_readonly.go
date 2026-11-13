package guest

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"

	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

// Existing read-only toolchains may themselves live in node_modules. Preserve
// only already-authorized reads, and freeze these trees read-only for the whole
// session: after exposing directory FDs, upgrading them to writes is unsafe.
func (d *Daemon) overlayReadRules(s *Session) []string {
	var reads []string
	for _, r := range []policy.Rules{d.store.Get(s.RulesFile), d.store.Get(system.GlobalRulesPath())} {
		r = withinCeiling(s.Landlock, r)
		reads = append(reads, r.Read...)
		reads = append(reads, r.Write...)
	}
	for _, b := range policy.Baseline(s.Project) {
		reads = append(reads, b.Pattern)
	}
	reads = append(reads, s.Launch...)
	if s.Learn {
		reads = append(reads, "/***")
	}
	return reads
}

func readOverlayCommands(target string, reads []string) []string {
	return policy.OverlayReadGuards(target, reads)
}

func (d *Daemon) prepareReadOverlay(s *Session, target string) error {
	if policy.OverlayWritable(target, d.concreteOverlayWrites(s)) {
		return errors.New("write scope changed while preparing read-only toolchain; retry")
	}
	if len(readOverlayCommands(target, d.overlayReadRules(s))) == 0 {
		return errors.New("no read grant for this toolchain")
	}
	if s.Learn && s.Landlock.Check("read", target+"/***") == nil && policy.ProtectedFor(s.Project, s.RulesFile, system.GlobalRulesPath()).Check("read", target+"/***") == nil {
		if _, _, err := d.store.Edit(s.RulesFile, policy.AddRule("read", target+"/***")); err != nil {
			return err
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !slices.Contains(s.OverlayReadOnly, target) {
		if len(s.OverlayReadOnly) >= maxLiveOverlays {
			return errors.New("too many read-only toolchains")
		}
		s.OverlayReadOnly = append(s.OverlayReadOnly, target)
	}
	meta, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(sessionsDir(), s.ID+".json"), meta, 0o600)
}
