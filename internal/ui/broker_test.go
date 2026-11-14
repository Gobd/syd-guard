package ui

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/guest"
)

func TestBrokerGitDoesNotUseRepositorySSHCommand(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_SSH_COMMAND", "")
	t.Setenv("GIT_SSH", "")
	project := filepath.Join(root, "project")
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// A fake trusted SSH on the HOST's PATH: the test never opens a network
	// connection or accesses the operator's SSH keys/configuration.
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\necho trusted-host-ssh >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	git(root, "init", "--separate-git-dir", filepath.Join(root, "admin"), project)
	git(project, "config", "user.name", "test")
	git(project, "config", "user.email", "test@example.invalid")
	git(project, "commit", "--allow-empty", "-m", "test")
	marker := filepath.Join(root, "unexpected-helper")
	git(project, "config", "core.sshCommand", "touch '"+marker+"'")
	git(project, "remote", "add", "origin", "ssh://test@example.invalid/repo")
	job := guest.Job{Project: project}
	res := (&uiServer{}).execute(&backend{}, job, []string{"git", "push", "origin", "HEAD"}, "")
	if !strings.Contains(res.Stderr, "trusted-host-ssh") {
		t.Fatalf("did not use host SSH: %+v", res)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("repository-controlled helper executed")
	}
	git(project, "remote", "set-url", "origin", "ext::touch "+marker)
	git(project, "config", "protocol.ext.allow", "always")
	res = (&uiServer{}).execute(&backend{}, job, []string{"git", "push", "origin", "HEAD"}, "")
	if !strings.Contains(res.Stderr, "transport 'ext' not allowed") {
		t.Fatalf("external transport not rejected: %+v", res)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("external transport helper executed")
	}
}

func TestBrokerPreservesExplicitHostSSH(t *testing.T) {
	t.Setenv("GIT_SSH_COMMAND", "ssh -F /trusted/config")
	var ssh string
	for _, item := range brokerEnvironment() {
		if value, ok := strings.CutPrefix(item, "GIT_SSH_COMMAND="); ok {
			ssh = value
		}
	}
	if ssh != "ssh -F /trusted/config" {
		t.Fatal("operator's SSH setup was lost")
	}
}
