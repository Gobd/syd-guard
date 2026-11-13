package guest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

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

func overlaySource(project, rel string) string {
	dir := filepath.Join(system.Home(), ".cache", "sydguard", "overlay", system.HashBytes([]byte(project))[:16], rel)
	_ = os.MkdirAll(dir, 0o755)
	return dir
}
