package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Gobd/syd-guard/internal/system"
)

// Landlock is an optional, immutable filesystem ceiling, not a source of Syd
// grants. Config paths extend the runtime/project/temp baseline. Session paths
// are the effective, canonicalized roots captured at launch. Read includes exec;
// write includes read. Live Syd approvals cannot expand these roots.
type Landlock struct {
	Enabled bool     `json:"enabled"`
	Read    []string `json:"read,omitempty"`
	Write   []string `json:"write,omitempty"`
}

func (l Landlock) Validate() error {
	for _, p := range append(slices.Clone(l.Read), l.Write...) {
		if err := system.SafePath(system.ExpandHome(p)); err != nil {
			return fmt.Errorf("landlock path %q: %w", p, err)
		}
		if strings.ContainsAny(p, "*?[]{}$\\") {
			return fmt.Errorf("landlock paths must be literal files/directories, not patterns: %q", p)
		}
	}
	return nil
}

// ResolveLandlock fails for missing configured roots. Optional system paths
// vary between distributions and are included only when present.
func ResolveLandlock(l Landlock, project string, launch []string) (Landlock, error) {
	if !l.Enabled {
		return Landlock{}, nil
	}
	if err := l.Validate(); err != nil {
		return Landlock{}, err
	}
	out := Landlock{Enabled: true}
	add := func(kind, p string, required bool) error {
		p = system.ExpandHome(p)
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			if !required && os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("landlock root %s: %w", p, err)
		}
		if kind == "write" {
			out.Write = append(out.Write, real)
		} else {
			out.Read = append(out.Read, real)
		}
		return nil
	}
	for _, p := range l.Read {
		if err := add("read", p, true); err != nil {
			return out, err
		}
	}
	for _, p := range l.Write {
		if err := add("write", p, true); err != nil {
			return out, err
		}
	}
	for _, b := range Baseline(project) {
		if err := add(b.Kind, strings.TrimSuffix(b.Pattern, "/***"), b.Kind == "write" && strings.TrimSuffix(b.Pattern, "/***") == project); err != nil {
			return out, err
		}
	}
	for _, p := range launch {
		if err := add("read", strings.TrimSuffix(p, "/***"), true); err != nil {
			return out, err
		}
	}
	// Character devices needed for normal terminal IO. This does not grant
	// access in Syd; it only keeps the kernel ceiling from blocking it.
	for _, p := range []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/ptmx", "/dev/pts"} {
		if err := add("write", p, false); err != nil {
			return out, err
		}
	}
	out.Read = slices.Compact(slices.Sorted(slices.Values(out.Read)))
	out.Write = slices.Compact(slices.Sorted(slices.Values(out.Write)))
	return out, nil
}

// Check conservatively requires the whole requested pattern to lie beneath a
// ceiling root. Resolve the existing ancestor to catch symlink escapes; glob
// grants spanning multiple roots must be split into separate approvals.
func (l Landlock) Check(kind, pattern string) error {
	if !l.Enabled || (kind != "read" && kind != "write") {
		return nil
	}
	pattern = system.ExpandHome(pattern)
	prefix := LiteralPrefix(pattern)
	if prefix == "" {
		prefix = "/"
	}
	roots := slices.Clone(l.Write)
	if kind == "read" {
		roots = append(roots, l.Read...)
	}
	prefix = filepath.Clean(prefix)
	real := prefix
	for {
		p, err := filepath.EvalSymlinks(real)
		if err == nil {
			real = filepath.Join(p, strings.TrimPrefix(strings.TrimPrefix(prefix, real), "/"))
			break
		}
		if !os.IsNotExist(err) || real == "/" {
			return fmt.Errorf("cannot verify Landlock ceiling for %s", pattern)
		}
		real = filepath.Dir(real)
	}
	for _, root := range roots {
		if system.Under(real, root) {
			return nil
		}
	}
	return fmt.Errorf("%s %s exceeds this session's Landlock ceiling; configure a wider ceiling and start a new session", kind, pattern)
}

// Commands sets the kernel ceiling once at startup. Runtime paths are not
// added to Syd's allow rules. Network access remains dynamically mediated by
// the session's TUN; this mode only adds a filesystem ceiling.
func (l Landlock) Commands() ([]string, error) {
	if !l.Enabled {
		return nil, nil
	}
	lines := []string{"sandbox/lock:on", "default/lock:kill", "allow/lock/bind+0-65535", "allow/lock/connect+0-65535"}
	for _, p := range l.Read {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		caps := []string{"read", "exec"}
		if fi.IsDir() {
			caps = append(caps, "readdir")
		}
		for _, cap := range caps {
			lines = append(lines, "allow/lock/"+cap+"+"+p)
		}
	}
	for _, p := range l.Write {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		caps := []string{"read", "exec", "write", "truncate"}
		if fi.IsDir() {
			caps = append(caps, "readdir", "create", "delete", "rename", "symlink", "mkdir", "rmdir", "mkfifo", "bind")
		}
		for _, cap := range caps {
			lines = append(lines, "allow/lock/"+cap+"+"+p)
		}
	}
	// Do not introduce an unrelated ioctl/Unix-connect ceiling. Syd's own
	// Unix-socket policy and the private network namespace still apply.
	return append(lines, "allow/lock/ioctl+/dev", "allow/lock/connect+/"), nil
}
