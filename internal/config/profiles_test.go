package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func profileEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "operator"))
}

func TestNamedProfilesDiscoverAncestorAndRemainUntrusted(t *testing.T) {
	profileEnvironment(t)
	root := t.TempDir()
	nested := filepath.Join(root, "pkg", "src")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := SelectProfile(root, "default", true)
	if err != nil {
		t.Fatal(err)
	}
	if first.Trusted {
		t.Fatal("discovered config silently trusted")
	}
	selected, err := SelectProfile(nested, "build", true)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(selected.Directory) != filepath.Dir(first.Directory) || selected.Path == first.Path {
		t.Fatalf("named discovery failed: %+v", selected)
	}
	if len(selected.Profile.Files) != 0 || len(selected.Profile.Network) != 0 {
		t.Fatal("new profile inherited permissions")
	}
	if err := TrustProfile(selected); err != nil {
		t.Fatal(err)
	}
	trusted, err := ReadProfile(selected.Path)
	if err != nil || !trusted.Trusted {
		t.Fatalf("review not retained: %v", err)
	}
	changed := selected.Profile
	changed.Network = []NetworkRule{{Host: "google.com", Port: 443, Transport: "tcp"}}
	data, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(selected.Path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	modified, err := ReadProfile(selected.Path)
	if err != nil {
		t.Fatal(err)
	}
	if modified.Trusted {
		t.Fatal("unreviewed config change retained trust")
	}
}

func TestMissingSelectedProfileIsEmptyWithoutCreatingFiles(t *testing.T) {
	profileEnvironment(t)
	root := t.TempDir()
	selected, err := SelectProfile(root, "build", false)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Profile.Name != "build" || selected.Profile.Version != 1 || len(selected.Profile.Files) != 0 || len(selected.Profile.Network) != 0 || selected.Trusted || selected.SHA256 != "" {
		t.Fatalf("missing profile was not empty and untrusted: %+v", selected)
	}
	if _, err := os.Lstat(selected.Path); !os.IsNotExist(err) {
		t.Fatalf("selection unexpectedly created a profile: %v", err)
	}
	if err := TrustProfile(selected); err == nil {
		t.Fatal("missing profile must not be trusted")
	}
}

func TestProfileRejectsTraversalAndSymlinkDirectory(t *testing.T) {
	profileEnvironment(t)
	root := t.TempDir()
	for _, name := range []string{"../wide", "default.json", "", "a/b", "a\nb"} {
		if name == "" {
			continue
		}
		if _, err := SelectProfile(root, name, true); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, ProfileFolder)); err != nil {
		t.Fatal(err)
	}
	if _, err := SelectProfile(root, "default", true); err == nil {
		t.Fatal("symlink config folder trusted")
	}
}
