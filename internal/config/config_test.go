package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(Path()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAndSecrets(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if c, err := Load(); err != nil || c.VM != "" || len(c.OverlayNames()) != 3 {
		t.Fatalf("missing config should be empty with default overlays: %+v %v", c, err)
	}
	secret := filepath.Join(dir, "tok")
	_ = os.WriteFile(secret, []byte("ghp_x\n"), 0o600)
	write(t, `{"vm":"dev","localPorts":[5173],"env":{"GH_TOKEN":"file:`+secret+`","PLAIN":"v"},"overlays":["node_modules"]}`)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	g, err := c.ForGuest()
	if err != nil || g.Env["GH_TOKEN"] != "ghp_x" || g.Env["PLAIN"] != "v" || g.VM != "" || g.LocalPorts[0] != 5173 {
		t.Fatalf("guest config: %+v %v", g, err)
	}
	for _, bad := range []string{`{"env":{"SYD_LOG":"x"}}`, `{"env":{"A B":"x"}}`, `{"localPorts":[0]}`, `{"overlays":["../x"]}`, `{"unknown":1}`} {
		write(t, bad)
		if _, err := Load(); err == nil {
			t.Errorf("config %s should be rejected", bad)
		}
	}
}
