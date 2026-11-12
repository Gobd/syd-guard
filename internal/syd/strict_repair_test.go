package syd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/config"
)

func TestStrictProjectRejectsRuntimeBaselineOverlap(t *testing.T) {
	temporary := t.TempDir()
	for _, project := range []string{"/usr", "/usr/bin", "/bin", "/etc", "/dev", "/lib", "/sbin"} {
		if info, err := os.Stat(project); err != nil || !info.IsDir() {
			continue
		}
		if _, err := StrictProfile(project, temporary, nil, config.ResolvedProfile{}); err == nil {
			t.Errorf("accepted runtime project %s", project)
		}
	}
	// Both directions for every path, including exact device nodes and aliases.
	for _, path := range append(append([]string(nil), runtimeExecutablePaths...), "/etc", "/dev/null", "/dev/random", "/dev/urandom") {
		for _, project := range []string{path, filepath.Dir(path), filepath.Join(path, "fixture-descendant")} {
			if !overlapsRuntimeBaseline(project) {
				t.Errorf("accepted overlap %s with %s", project, path)
			}
		}
		canonical, err := config.RevalidateResolvedFilePath(path)
		if err == nil && !overlapsRuntimeBaseline(canonical) {
			t.Errorf("accepted canonical alias %s", canonical)
		}
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink("/usr", alias); err != nil {
		t.Fatal(err)
	}
	if _, err := StrictProfile(alias, temporary, nil, config.ResolvedProfile{}); err == nil {
		t.Fatal("accepted symlink alias of runtime")
	}
	work := t.TempDir()
	profile, err := StrictProfile(work, temporary, nil, config.ResolvedProfile{})
	if err != nil {
		t.Fatal(err)
	}
	work, _ = filepath.EvalSymlinks(work)
	if strings.Contains(profile, "allow/read,stat,readdir,readlink,chdir,write,create,delete,rename,truncate,chmod,chattr,mkdir,rmdir,symlink+"+work) || strings.Contains(profile, "allow/read,stat,readdir,readlink,chdir,exec+"+work) {
		t.Fatal("empty profile granted project contents")
	}
}

func TestStrictProtectedEngineAndWrapperOverlap(t *testing.T) {
	work, temporary := t.TempDir(), t.TempDir()
	for _, name := range []string{"syd", "wrapper"} {
		protected := filepath.Join(work, name)
		if err := os.WriteFile(protected, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, recursive := range []bool{false, true} {
			resolved := resolveStrictFixture(t, work, []config.FileRule{{Path: ".", Access: []string{"read"}, Recursive: recursive}})
			_, err := StrictProfile(work, temporary, []string{protected}, resolved)
			if err == nil || !strings.Contains(err.Error(), "outside the rule hierarchy") {
				t.Fatalf("protected %s recursive=%v: %v", name, recursive, err)
			}
		}
	}
}

func TestCloneResolvedProfileOwnsSlices(t *testing.T) {
	original := config.ResolvedProfile{Files: []config.FileRule{{Path: "/a", Access: []string{"read", "write"}}}, Network: []config.NetworkRule{{Host: "example.com", Port: 443, Transport: "tcp"}}}
	owned := cloneResolvedProfile(original)
	original.Files[0].Path = "/b"
	original.Files[0].Access[0] = "delete"
	original.Network[0].Host = "changed.example"
	if owned.Files[0].Path != "/a" || owned.Files[0].Access[0] != "read" || owned.Network[0].Host != "example.com" {
		t.Fatal("clone aliases caller slices")
	}
	owned.Files[0].Access[1] = "read"
	if original.Files[0].Access[1] != "write" {
		t.Fatal("caller aliases clone")
	}
}

func TestStrictRuntimeAuthorizationAndLegacyGate(t *testing.T) {
	profile := config.ResolvedProfile{}
	for _, opts := range []RunOptions{{ReadInputs: []string{"/x"}}, {ExecInputs: []string{"/x"}}, {Scopes: []string{"/x"}}} {
		opts.ResolvedProfile = &profile
		if _, err := Run(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "rejects legacy") {
			t.Fatalf("legacy accepted: %v", err)
		}
	}
	if _, err := Run(context.Background(), RunOptions{ResolvedProfile: &profile, StrictInputs: TrustedRuntimeInputs{Read: []string{"/x"}}}); err == nil || !strings.Contains(err.Error(), "authorization callback") {
		t.Fatalf("missing authorization accepted: %v", err)
	}
	sentinel := errors.New("stop after handoff")
	inputs := TrustedRuntimeInputs{Read: []string{"/x"}, Exec: []string{"/y"}}
	ipc := &HumanIPCApprovals{Scopes: []string{"/z"}}
	var metadata StrictRuntimeCapabilities
	_, err := Run(context.Background(), RunOptions{ResolvedProfile: &profile, StrictInputs: inputs, StrictIPC: ipc, OnStrictRuntimeCapabilities: func(m StrictRuntimeCapabilities) error { metadata = m; m.Inputs.Read[0] = "/mutated"; return sentinel }})
	if !errors.Is(err, sentinel) || inputs.Read[0] != "/x" || !reflect.DeepEqual(metadata.IPCScopes, []string{"/z"}) || !containsCapability(metadata.IPCCeilingCapabilities, "exec") {
		t.Fatalf("unexpected metadata: %+v, err=%v", metadata, err)
	}
}
