//go:build linux

package guest

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

// Opt-in real-engine regressions. No installed namespace helper or running
// sydguard daemon is needed; all files, IPC and HOME are private to each test.
func securityEngine(t *testing.T) string {
	t.Helper()
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if engine == "" {
		t.Skip("set SYDGUARD_TEST_SYD to a Syd 3.59 binary for real-engine regressions")
	}
	out, err := exec.Command(engine, "--version").Output()
	if err != nil || !strings.HasPrefix(string(out), "syd "+SydVersion) {
		t.Fatalf("need Syd %s: %v: %s", SydVersion, err, out)
	}
	return engine
}

func securityProject(t *testing.T) (string, string) {
	t.Helper()
	root, err := os.MkdirTemp("", "sydguard-security-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Log("security test artifacts:", root)
		} else {
			_ = os.RemoveAll(root)
		}
	})
	home, project := filepath.Join(root, "home"), filepath.Join(root, "project")
	for _, dir := range []string{home, project} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	return root, project
}

func securityProfile(t *testing.T, root, project, ipc string, rules policy.Rules, learn bool) string {
	t.Helper()
	profile, err := policy.CompileProfile(policy.ProfileInput{
		Project: project, IPC: ipc, Protect: policy.ProtectedFor(project), Rules: []policy.Rules{rules}, Learn: learn,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "test.syd-3")
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func securityEnv() []string { return []string{"HOME=" + system.Home(), "PATH=/usr/bin:/bin", "LANG=C"} }

func TestSecurityGitMetadataAndNormalCommit(t *testing.T) {
	engine := securityEngine(t)
	root, project := securityProject(t)
	cmd := exec.Command("git", "init", "-q", project)
	cmd.Env = securityEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("init: %v: %s", err, out)
	}
	profile := securityProfile(t, root, project, "@security-"+system.NewID(), policy.Rules{}, false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, engine, "-P", profile, "--", "/bin/sh", "-c", `
set -eu
if mv .git alternate-admin 2>/dev/null; then echo 'renamed protected .git'; exit 1; fi
if echo tampered > .git/config 2>/dev/null; then echo 'wrote protected config'; exit 1; fi
echo hello > sample.txt
git add sample.txt
git -c user.name=test -c user.email=test@example.invalid -c commit.gpgsign=false commit -qm test
`)
	cmd.Dir, cmd.Env = project, securityEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("normal commit / metadata guards: %v: %s", err, out)
	}
	// A real linked worktree: the gitfile and common-directory config must be
	// protected, while normal worktree commits still work. The scratch files
	// are in /tmp, so outside-project metadata is otherwise baseline-writable.
	pointerProject := filepath.Join(root, "worktree")
	cmd = exec.CommandContext(ctx, "git", "-C", project, "worktree", "add", "-q", "-b", "test", pointerProject)
	cmd.Env = securityEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("worktree setup: %v: %s", err, out)
	}
	profile = securityProfile(t, root, pointerProject, "@security-"+system.NewID(), policy.Rules{}, false)
	cmd = exec.CommandContext(ctx, engine, "-P", profile, "--", "/bin/sh", "-c", `
set -eu
if printf 'gitdir: ./alternate-admin\n' > .git 2>/dev/null; then exit 1; fi
if mv .git old-pointer 2>/dev/null; then exit 1; fi
if echo tampered > ../project/.git/config 2>/dev/null; then exit 1; fi
if echo tampered > ../project/.git/worktrees/worktree/config.worktree 2>/dev/null; then exit 1; fi
if echo ../elsewhere > ../project/.git/worktrees/worktree/commondir 2>/dev/null; then exit 1; fi
echo worktree-change >> sample.txt
git add sample.txt
git -c user.name=test -c user.email=test@example.invalid -c commit.gpgsign=false commit -qm worktree-test
`)
	cmd.Dir, cmd.Env = pointerProject, securityEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gitfile guards: %v: %s", err, out)
	}
}

func TestSecurityInitialPathDenies(t *testing.T) {
	engine := securityEngine(t)
	for _, learn := range []bool{false, true} {
		root, project := securityProject(t)
		secret := filepath.Join(project, "secret.env")
		if err := os.WriteFile(secret, []byte("dummy-only\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		profile := securityProfile(t, root, project, "@security-"+system.NewID(), policy.Rules{Ignore: []string{secret}}, learn)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, engine, "-P", profile, "--", "/bin/sh", "-c", `
if cat secret.env >/dev/null 2>&1; then echo readable; exit 1; fi
if echo replacement > secret.env 2>/dev/null; then echo writable; exit 1; fi
`)
		cmd.Dir, cmd.Env = project, securityEnv()
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("initial deny (learn=%v): %v: %s", learn, err, out)
		}
	}
}

func TestSecurityPathDenyLiveUpdates(t *testing.T) {
	engine := securityEngine(t)
	root, project := securityProject(t)
	secret := filepath.Join(project, "secret.env")
	if err := os.WriteFile(secret, []byte("dummy-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ipc := "@security-" + system.NewID()
	profile := securityProfile(t, root, project, ipc, policy.Rules{}, false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, engine, "-P", profile, "--", "/bin/sh", "-c", `
while ! test -e finish; do
  if cat secret.env >/dev/null 2>&1; then echo allowed > result.tmp; else echo denied > result.tmp; fi
  mv result.tmp result
  sleep 0.05
done
`)
	cmd.Dir, cmd.Env = project, securityEnv()
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Log(log.String())
		}
	})
	wait := func(want string) {
		t.Helper()
		until := time.Now().Add(5 * time.Second)
		for time.Now().Before(until) {
			data, _ := os.ReadFile(filepath.Join(project, "result"))
			if strings.TrimSpace(string(data)) == want {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("did not observe %s", want)
	}
	load := func(lines []string) {
		t.Helper()
		f, err := os.CreateTemp(root, "batch-")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		if err := LoadFD(ipc, f); err != nil {
			t.Fatal(err)
		}
	}
	wait("allowed")
	s := &Session{Project: project, RulesFile: filepath.Join(project, policy.DefaultRulesName)}
	d := &Daemon{store: policy.NewStore()}
	before, after, err := d.store.Edit(s.RulesFile, policy.AddRule("ignore", secret))
	if err != nil {
		t.Fatal(err)
	}
	load(d.withGuards(s, policy.DiffCommands(before, after)))
	wait("denied")
	load(d.withGuards(s, policy.SydCommands("write", project+"/***", "+")))
	// Wait for fresh results, not the result from before the broad grant.
	_ = os.Remove(filepath.Join(project, "result"))
	wait("denied")
	// Removing a project deny must not remove an identical global deny.
	if _, _, err := d.store.Edit(system.GlobalRulesPath(), policy.AddRule("ignore", secret)); err != nil {
		t.Fatal(err)
	}
	before, after, err = d.store.Edit(s.RulesFile, policy.RemoveRule("ignore", secret))
	if err != nil {
		t.Fatal(err)
	}
	load(d.withGuards(s, policy.DiffCommands(before, after)))
	_ = os.Remove(filepath.Join(project, "result"))
	wait("denied")
	before, after, err = d.store.Edit(system.GlobalRulesPath(), policy.RemoveRule("ignore", secret))
	if err != nil {
		t.Fatal(err)
	}
	load(d.withGuards(s, policy.DiffCommands(before, after)))
	wait("allowed")
}
