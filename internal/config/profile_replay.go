package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// ResolvedProfile is a launch-local translation of reviewed logical intent.
// It does not install grants or supply runtime network addresses.
type ResolvedProfile struct {
	Files   []FileRule
	Network []NetworkRule
}

// ResolveProfile resolves file rules under explicit existing ceilings, rejecting
// any overlap with protected paths. The caller must revalidate paths when
// installing grants and enforce separate immutable kernel ceilings.
func ResolveProfile(snapshot ProfileSnapshot, project, home string, ceilings, protected []string) (ResolvedProfile, error) {
	if snapshot.revision == "" {
		return ResolvedProfile{}, fmt.Errorf("missing reviewed profile")
	}
	project, err := existingDirectory(project)
	if err != nil {
		return ResolvedProfile{}, err
	}
	if home != "" {
		home, err = existingDirectory(home)
		if err != nil {
			return ResolvedProfile{}, err
		}
	}
	roots := make([]string, 0, len(ceilings))
	for _, root := range ceilings {
		root, err = existingDirectory(root)
		if err != nil {
			return ResolvedProfile{}, err
		}
		roots = append(roots, root)
	}
	blocked := make([]string, 0, len(protected))
	for _, path := range protected {
		path, err = resolveExistingPrefix(path)
		if err != nil {
			return ResolvedProfile{}, err
		}
		blocked = append(blocked, path)
	}
	profile := snapshot.Profile()
	result := ResolvedProfile{Network: append([]NetworkRule(nil), profile.Network...)}
	for _, rule := range profile.Files {
		path := rule.Path
		if path == "~" || strings.HasPrefix(path, "~/") {
			if home == "" {
				return ResolvedProfile{}, fmt.Errorf("home is required for tilde paths")
			}
			path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
			if rule.Path == "~" {
				path = home
			}
		} else if !filepath.IsAbs(path) {
			path = filepath.Join(project, path)
		}
		path, err = resolveExistingPrefix(path)
		if err != nil {
			return ResolvedProfile{}, err
		}
		if path == "/" {
			return ResolvedProfile{}, fmt.Errorf("filesystem root cannot be granted")
		}
		if strings.ContainsAny(path, "*?[]{}\\$;!") || strings.IndexFunc(path, unicode.IsControl) >= 0 {
			return ResolvedProfile{}, fmt.Errorf("resolved path is not a literal Syd path")
		}
		allowed := false
		for _, root := range roots {
			if pathWithin(path, root) {
				allowed = true
				break
			}
		}
		if !allowed {
			return ResolvedProfile{}, fmt.Errorf("file rule outside declared ceiling")
		}
		for _, denied := range blocked {
			if pathWithin(path, denied) || pathWithin(denied, path) {
				return ResolvedProfile{}, fmt.Errorf("file rule overlaps protected path")
			}
		}
		rule.Path = path
		rule.Access = append([]string(nil), rule.Access...)
		result.Files = append(result.Files, rule)
	}
	return result, nil
}

func existingDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("directory must be absolute")
	}
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("not a directory")
	}
	return path, nil
}

func resolveExistingPrefix(path string) (string, error) {
	if !filepath.IsAbs(path) || hasParentComponent(path) {
		return "", fmt.Errorf("path must be absolute and contain no parent components")
	}
	path = filepath.Clean(path)
	parent := path
	var missing []string
	for {
		_, err := os.Lstat(parent)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		next := filepath.Dir(parent)
		if next == parent {
			return "", fmt.Errorf("no existing path ancestor")
		}
		missing = append(missing, filepath.Base(parent))
		parent = next
	}
	parent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	for i := len(missing) - 1; i >= 0; i-- {
		parent = filepath.Join(parent, missing[i])
	}
	return parent, nil
}

func pathWithin(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
