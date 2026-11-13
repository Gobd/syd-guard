package policy

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Gobd/syd-guard/internal/system"
)

// Configured build-folder names are reserved until backed by verified storage.
func ValidOverlayName(name string) bool {
	return system.SafeText(name) == nil && name != "." && name != ".." && name != ".git" && !strings.ContainsAny(name, "/:*?[]{}\\")
}

func OverlayTarget(names []string, path string) string {
	if !filepath.IsAbs(path) {
		return ""
	}
	current := ""
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		current += "/" + part
		if slices.Contains(names, part) {
			return current
		}
	}
	return ""
}

// OverlayWritable deliberately requires a literal recursive grant. Granting a
// single file or a narrow glob must never turn into a whole-directory exemption.
func OverlayWritable(target string, writes []string) bool {
	for _, pattern := range writes {
		if !strings.HasSuffix(pattern, "/***") {
			continue
		}
		root := strings.TrimSuffix(pattern, "/***")
		if root == "" {
			root = "/"
		}
		if !strings.ContainsAny(root, "*?[]{}\\") && system.Under(target, root) {
			return true
		}
	}
	return false
}

// OverlayReadGuards preserves existing read grants for installed toolchains,
// while keeping their tree permanently non-writable for this session.
func OverlayReadGuards(target string, reads []string) []string {
	if system.SafePath(target) != nil || strings.ContainsAny(target, "*?[]{}\\") {
		return nil
	}
	var out []string
	for _, p := range reads {
		switch {
		case OverlayWritable(target, []string{p}):
			out = append(out, SydCommands("read", target+"/***", "+")...)
		case system.Under(LiteralPrefix(p), target):
			out = append(out, SydCommands("read", p, "+")...)
		}
	}
	if len(out) == 0 {
		return nil
	}
	out = append(out, "allow/stat+"+target+"/***", "deny/"+ModifyCaps+"+"+target+"/***")
	return append(out, OverlayPathLocks(target)...)
}

func OverlayPathLocks(target string) []string {
	var out []string
	for p := target; p != "/"; p = filepath.Dir(p) {
		out = append(out, "deny/rename,delete,rmdir,symlink+"+p)
	}
	return out
}

// OverlayGuards must follow ordinary grants and precede protected-path denies.
// Syd uses last matching rule wins. Reinstall the broad denies on every update,
// then exempt only verified mounts whose write scope is still authorized.
func OverlayGuards(names, mounted, writes []string) ([]string, error) {
	var out []string
	for _, name := range names {
		if !ValidOverlayName(name) {
			return nil, fmt.Errorf("invalid overlay name %q", name)
		}
		out = append(out, "deny/"+WriteCaps+"+/**/"+name+"/***")
	}
	for _, target := range mounted {
		if system.SafePath(target) != nil || strings.ContainsAny(target, "*?[]{}\\") {
			return nil, fmt.Errorf("overlay target must be a literal path: %q", target)
		}
		if !OverlayWritable(target, writes) {
			continue
		}
		out = append(out, "allow/"+WriteCaps+"+"+target+"/***")
		// Keep the mount pathname stable. Without ancestor guards the agent could
		// move its parent away and recreate an unmounted directory at the exemption.
		out = append(out, OverlayPathLocks(target)...)
	}
	return out, nil
}
