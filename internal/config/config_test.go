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
	write(t, `{"vm":"dev","localPorts":[5173],"env":{"GH_TOKEN":"file:`+secret+`","PLAIN":"v"},"keepOnVM":["node_modules"]}`)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	g, err := c.ForGuest()
	if err != nil || g.Env["GH_TOKEN"] != "ghp_x" || g.Env["PLAIN"] != "v" || g.VM != "" || g.Backend != "native" || g.LocalPorts[0] != 5173 {
		t.Fatalf("guest config: %+v %v", g, err)
	}
	for _, bad := range []string{`{"env":{"SYD_LOG":"x"}}`, `{"env":{"A B":"x"}}`, `{"localPorts":[0]}`, `{"keepOnVM":["../x"]}`, `{"unknown":1}`, `{"backend":"auto"}`, `{"landlock":{"enabled":true,"read":["relative"]}}`, `{"landlock":{"enabled":true,"write":["/tmp/***"]}}`} {
		write(t, bad)
		if _, err := Load(); err == nil {
			t.Errorf("config %s should be rejected", bad)
		}
	}
}

// Every shipped machine config must remain valid and sync its ceiling to guests.
func TestExampleConfigs(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	files, err := filepath.Glob("../../examples/config*.json")
	if err != nil || len(files) != 5 {
		t.Fatalf("examples: %v %v", files, err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			write(t, string(data))
			c, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if filepath.Base(file) != "config.json" && len(c.Commands) != 0 {
				t.Fatal("starter config must not authorize host commands")
			}
			guest, err := c.ForGuest()
			if err != nil {
				t.Fatal(err)
			}
			if guest.Backend != "native" || guest.VM != "" || guest.Lima != "" || guest.Landlock.Enabled != c.Landlock.Enabled || len(guest.Landlock.Read) != len(c.Landlock.Read) || len(guest.Landlock.Write) != len(c.Landlock.Write) {
				t.Fatalf("bad guest config: %+v", guest)
			}
		})
	}
}
