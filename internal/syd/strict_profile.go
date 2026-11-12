package syd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Gobd/syd-guard/internal/config"
)

// Keep the platform gate indirect so unsupported-platform stubs remain buildable
// without static analysis mistaking their unconditional rejection for a bug.
var strictReplayLandlockGate = strictLandlockGate

// StrictProfile compiles a caller-authorized, launch-local resolved snapshot.
// It neither discovers nor authorizes profiles, and ignores logical network
// intent. Revalidation is not atomic with launch or runtime: renames, symlinks
// and mounts can change. Path rules cannot protect preexisting hardlinks to
// protected inodes. Deploy the engine, wrapper and other protected authorities
// outside any file-rule ancestor; overlap is rejected even for exact rules.
func StrictProfile(workdir, temporary string, protected []string, resolved config.ResolvedProfile) (string, error) {
	workdir, err := canonicalDirectory(workdir)
	if err != nil {
		return "", err
	}
	temporary, err = canonicalDirectory(temporary)
	if err != nil {
		return "", err
	}
	if workdir == "/" {
		return "", fmt.Errorf("filesystem root cannot be a working directory")
	}
	if pathOverlaps(workdir, temporary) {
		return "", fmt.Errorf("temporary directory must not overlap the project")
	}
	if overlapsRuntimeBaseline(workdir) {
		return "", fmt.Errorf("project overlaps trusted runtime baseline; choose a disjoint project directory")
	}
	if overlapsRuntimeExecutablePath(temporary) {
		return "", fmt.Errorf("temporary directory overlaps trusted runtime execution")
	}
	lines, err := runtimeRules()
	if err != nil {
		return "", err
	}
	lines = append(lines, writableRuntimeRules(temporary, false)...)
	lines = append(lines, "allow/stat,chdir+"+workdir)
	for _, rule := range resolved.Files {
		path := rule.Path
		if path == "/" || filepath.Clean(path) != path || literalPath(path) != nil {
			return "", fmt.Errorf("invalid resolved file path: %q", path)
		}
		current, err := config.RevalidateResolvedFilePath(path)
		if err != nil || current != path {
			return "", fmt.Errorf("resolved file path changed: %q", path)
		}
		for _, blocked := range protected {
			canonical, err := config.RevalidateResolvedFilePath(blocked)
			if err != nil || pathOverlaps(path, canonical) {
				return "", fmt.Errorf("file rule overlaps or cannot validate protected authority; place engine, wrapper and state outside the rule hierarchy and review ceilings")
			}
		}
		caps, err := ExpandFileAccess(rule.Access)
		if err != nil {
			return "", err
		}
		// Common metadata operations used by chmod and other mutation tools
		// need stat even when the public read group was not selected.
		if !containsCapability(caps, "stat") {
			caps = append(caps, "stat")
		}
		for _, group := range rule.Access {
			if (group == "write" || group == "delete") && overlapsRuntimeExecutablePath(path) {
				return "", fmt.Errorf("mutation rule overlaps trusted runtime execution: %s", path)
			}
		}
		if home, err := os.UserHomeDir(); err == nil {
			if home, err = filepath.EvalSymlinks(home); err == nil && (path == home || rule.Recursive && pathOverlaps(path, home) && strings.HasPrefix(home, path+string(filepath.Separator))) {
				for _, group := range rule.Access {
					if group == "write" || group == "delete" {
						return "", fmt.Errorf("refusing writable whole-home rule")
					}
				}
			}
		}
		// Landlock controls file hierarchies rather than exact syscall paths.
		// For an absent target or an exact target, the existing parent must be
		// eligible for creation/removal; Syd's path rules remain exact.
		ceiling := path
		info, statErr := os.Stat(path)
		if statErr != nil && !os.IsNotExist(statErr) {
			return "", statErr
		}
		if statErr != nil || !info.IsDir() || !rule.Recursive {
			ceiling = filepath.Dir(path)
		}
		for {
			info, err := os.Stat(ceiling)
			if err == nil && info.IsDir() {
				break
			}
			if err != nil && !os.IsNotExist(err) {
				return "", err
			}
			next := filepath.Dir(ceiling)
			if next == ceiling {
				return "", fmt.Errorf("no eligible Landlock directory")
			}
			ceiling = next
		}
		if ceiling == "/" {
			return "", fmt.Errorf("file rule requires root Landlock ceiling")
		}
		var locks []string
		for _, group := range rule.Access {
			switch group {
			case "read":
				locks = append(locks, "read", "readdir")
			case "write":
				locks = append(locks, "write", "create", "truncate", "mkdir", "symlink")
			case "delete":
				locks = append(locks, "delete", "rmdir", "rename")
			}
		}
		for ancestor := filepath.Dir(path); ancestor != "/"; ancestor = filepath.Dir(ancestor) {
			lines = append(lines, "allow/stat,chdir+"+ancestor)
		}
		lines = append(lines, "allow/"+strings.Join(caps, ",")+"+"+path)
		if rule.Recursive {
			lines = append(lines, "allow/"+strings.Join(caps, ",")+"+"+path+"/***")
		}
		lines = append(lines, "allow/lock/"+strings.Join(locks, ",")+"+"+ceiling)
	}
	denies, err := ProtectedRules(workdir, protected)
	if err != nil {
		return "", err
	}
	return strings.Join(lines, "\n") + "\n" + denies, nil
}

// Include both the spelling used by the profile and its canonical alias.
func overlapsRuntimeBaseline(path string) bool {
	paths := append(append([]string(nil), runtimeExecutablePaths...), "/etc", "/dev/null", "/dev/random", "/dev/urandom")
	for _, runtimePath := range paths {
		if pathOverlaps(path, runtimePath) {
			return true
		}
		resolved, err := config.RevalidateResolvedFilePath(runtimePath)
		if err != nil || pathOverlaps(path, resolved) {
			return true
		}
	}
	return false
}

func overlapsRuntimeExecutablePath(path string) bool {
	for _, runtimePath := range runtimeExecutablePaths {
		resolved, err := filepath.EvalSymlinks(runtimePath)
		if err == nil && pathOverlaps(path, resolved) {
			return true
		}
	}
	return false
}

func containsCapability(caps []string, capability string) bool {
	for _, cap := range caps {
		if cap == capability {
			return true
		}
	}
	return false
}
