package policy

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestGitMetadataProtection(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "checkout")
	common := filepath.Join(root, "main", ".git")
	admin := filepath.Join(common, "worktrees", "checkout")
	for _, dir := range []string{project, admin} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string]string{
		filepath.Join(project, ".git"):    "gitdir: ../main/.git/worktrees/checkout\n",
		filepath.Join(admin, "commondir"): "../..\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := ProtectedFor(project)
	for _, path := range []string{project, filepath.Join(project, ".git"), admin, common} {
		if !slices.Contains(p.NoWriteExact, path) || p.Check("write", path) == nil {
			t.Errorf("entry not protected: %s", path)
		}
	}
	for _, dir := range []string{admin, common} {
		for _, path := range []string{"config", "config.worktree", "commondir", "gitdir", "hooks/pre-push"} {
			if p.Check("write", filepath.Join(dir, path)) == nil {
				t.Errorf("metadata writable: %s/%s", dir, path)
			}
		}
		for _, path := range []string{"index", "HEAD", "objects/***", "refs/***"} {
			if err := p.Check("write", filepath.Join(dir, path)); err != nil {
				t.Errorf("ordinary Git data blocked: %v", err)
			}
		}
	}
}

func TestGitDirectoryProtectionIsNotRecursive(t *testing.T) {
	p := ProtectedFor("/project")
	commands := p.Commands()
	if !slices.Contains(commands, "deny/"+ModifyCaps+"+/project/.git") {
		t.Fatal(".git can be replaced")
	}
	if slices.Contains(commands, "deny/"+ModifyCaps+"+/project/.git/***") {
		t.Fatal("normal commits would be blocked")
	}
	if err := p.Check("write", "/project/.git/refs/***"); err != nil {
		t.Fatal(err)
	}
}
