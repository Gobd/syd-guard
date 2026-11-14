package policy

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Gobd/syd-guard/internal/system"
)

// protectGit protects Git's metadata entry points without blocking ordinary
// index/object/ref updates. In worktrees and submodules .git is a pointer FILE;
// protecting only .git/config does not protect the actual configuration.
// Never run Git here: repository discovery must not execute repository code.
func protectGit(p Protection, project string) Protection {
	entry := filepath.Join(project, ".git")
	p.NoWriteExact = append(p.NoWriteExact, project, entry)
	dir := entry
	if target := gitPointer(entry, "gitdir: "); target != "" {
		dir = target
	}
	// Keep both the lexical name and its resolved target protected.
	protectDir := func(dir string) {
		p.NoWriteExact = append(p.NoWriteExact, dir)
		for _, name := range []string{"config", "config.worktree", "commondir", "gitdir", "hooks"} {
			p.NoWrite = append(p.NoWrite, filepath.Join(dir, name))
		}
	}
	protectDir(dir)
	if real, err := filepath.EvalSymlinks(dir); err == nil && system.SafePath(real) == nil && real != dir {
		protectDir(real)
	}
	if common := gitPointer(filepath.Join(dir, "commondir"), ""); common != "" {
		protectDir(common)
		if real, err := filepath.EvalSymlinks(common); err == nil && system.SafePath(real) == nil && real != common {
			protectDir(real)
		}
	}
	return p
}

// gitPointer reads a bounded, existing regular pointer file. Relative targets
// are relative to the pointer's parent, as in Git's gitdir/commondir formats.
func gitPointer(path, prefix string) string {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 4096 {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return ""
	}
	target, ok := strings.CutPrefix(strings.TrimSpace(string(data)), prefix)
	if !ok || target == "" {
		return ""
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	target = filepath.Clean(target)
	if system.SafePath(target) != nil || strings.ContainsAny(target, "*?[]{}") {
		return ""
	}
	return target
}
