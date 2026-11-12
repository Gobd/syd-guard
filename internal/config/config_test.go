package config

import (
	"os"
	"path/filepath"
	"testing"
)

func privateHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

func TestDefaultDoesNotWriteAndSaveRoundTrip(t *testing.T) {
	privateHome(t)
	settings, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("load created config: %v", err)
	}
	if err := Save(settings); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil || got != settings {
		t.Fatalf("roundtrip %+v %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config is not private: %v %v", info, err)
	}
}

func TestRejectSymlinkAndPublicConfig(t *testing.T) {
	privateHome(t)
	settings, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(settings); err != nil {
		t.Fatal(err)
	}
	path, _ := Path()
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // test proves that insecure operator config permissions are rejected
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("public config accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "other"), path); err != nil {
		t.Fatal(err)
	}
	if err := Save(settings); err == nil {
		t.Fatal("config symlink overwritten")
	}
}

func TestRecipeFingerprintDetectsChanges(t *testing.T) {
	privateHome(t)
	file := filepath.Join(t.TempDir(), "recipe.yaml")
	if err := os.WriteFile(file, []byte("cpus: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, hash, err := ResolveRecipe(file)
	if err != nil || !filepath.IsAbs(path) || len(hash) != 64 {
		t.Fatalf("%s %s %v", path, hash, err)
	}
	if err := os.WriteFile(file, []byte("cpus: 4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, changed, err := ResolveRecipe(file)
	if err != nil || changed == hash {
		t.Fatalf("change not detected: %v", err)
	}
}
