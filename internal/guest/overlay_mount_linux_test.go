package guest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureOverlayDirRefusesLinks(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "node_modules")
	if err := ensureOverlayDir(target, true); err != nil {
		t.Fatal(err)
	}
	if err := ensureOverlayDir(target, false); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, filepath.Join(link, "nested")} {
		if err := ensureOverlayDir(p, true); err == nil {
			t.Fatalf("followed symlink: %s", p)
		}
	}
	if _, err := os.Stat(filepath.Join(target, "nested")); !os.IsNotExist(err) {
		t.Fatal("created through symlink")
	}
}
