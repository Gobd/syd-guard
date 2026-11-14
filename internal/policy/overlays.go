package policy

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/Gobd/syd-guard/internal/system"
)

// OverlayRoot returns the first keepOnVM-named folder containing path, below
// one of roots (the host shares), e.g. /share/p/web/node_modules for a file in it.
func OverlayRoot(roots, names []string, path string) string {
	for _, r := range roots {
		rel, err := filepath.Rel(r, path)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			continue
		}
		dir := r
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			dir = filepath.Join(dir, part)
			if slices.Contains(names, part) {
				return dir
			}
		}
	}
	return ""
}

// OverlayGuards keeps keepOnVM folders under roots (the host shares) read-only
// until VM storage backs them, whichever grant made them writable. They go
// after ordinary grants (Syd: last match wins), before protected denies. Reads
// stay allowed: an existing host copy is still usable, just not changed.
func OverlayGuards(roots, names, mounted []string) []string {
	var out []string
	for _, r := range roots {
		if r == "/" || system.SafePath(r) != nil {
			continue
		}
		for _, n := range names {
			out = append(out, "deny/"+ModifyCaps+"+"+r+"/"+n+"/***", "deny/"+ModifyCaps+"+"+r+"/**/"+n+"/***")
		}
	}
	if len(out) == 0 {
		return nil
	}
	for _, m := range mounted {
		out = append(out, "allow/"+ModifyCaps+"+"+m+"/***")
	}
	return out
}
