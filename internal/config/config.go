// Package config reads ~/.config/sydguard/config.json: machine-wide defaults
// for the VM, local helper ports, secrets passed to agents as env vars, and
// which build folders stay on the VM disk. The sandbox can't read it.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

type Config struct {
	Backend    string            `json:"backend,omitempty"`    // lima (default outside guests) or native (Linux only)
	Landlock   policy.Landlock   `json:"landlock,omitempty"`   // optional fixed filesystem ceiling
	VM         string            `json:"vm,omitempty"`         // Lima instance
	Lima       string            `json:"lima,omitempty"`       // Lima file to create it from
	LocalPorts []int             `json:"localPorts,omitempty"` // like --local-port, for every run
	Env        map[string]string `json:"env,omitempty"`        // NAME: "value" or "file:PATH" (secret file)
	PassEnv    []string          `json:"passEnv,omitempty"`    // explicit inherited variables, including credentials
	Overlays   []string          `json:"keepOnVM,omitempty"`   // folders kept on the VM disk, not the project (node_modules…)
	// Commands agents may ask to run on this machine (`sydguard cmd NAME`),
	// for every project. Per-project ones live in rules files.
	Commands map[string]policy.Command `json:"commands,omitempty"`
}

// DefaultOverlays: node_modules next to every package.json, .venv for Python,
// target for Rust.
var DefaultOverlays = []string{"node_modules", ".venv", "target"}

func Path() string { return filepath.Join(system.ConfigDir(), "config.json") }

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Load reads the config; a missing file is an empty config.
func Load() (Config, error) {
	var c Config
	data, err := os.ReadFile(Path())
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	} else if err != nil {
		return c, err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", Path(), err)
	}
	return c, c.validate()
}

func (c Config) validate() error {
	if c.Backend != "" && c.Backend != "lima" && c.Backend != "native" {
		return fmt.Errorf("%s: backend must be lima or native", Path())
	}
	if err := c.Landlock.Validate(); err != nil {
		return err
	}
	for _, p := range c.LocalPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("%s: bad local port %d", Path(), p)
		}
	}
	for _, k := range c.PassEnv {
		if !ValidPassEnv(k) {
			return fmt.Errorf("%s: bad passEnv name %q", Path(), k)
		}
	}
	for k := range c.Env {
		if !ValidPassEnv(k) {
			return fmt.Errorf("%s: bad env name %q", Path(), k)
		}
	}
	if err := policy.ValidateCommands(c.Commands); err != nil {
		return fmt.Errorf("%s: %w", Path(), err)
	}
	for _, o := range c.Overlays {
		if o == "" || strings.ContainsAny(o, "/:") || o == "." || o == ".." || o == ".git" {
			return fmt.Errorf("%s: keepOnVM entries must be plain folder names, got %q", Path(), o)
		}
	}
	return nil
}

// OverlayNames is the configured list, or the default.
func (c Config) OverlayNames() []string {
	if c.Overlays == nil {
		return DefaultOverlays
	}
	return c.Overlays
}

// ResolvedEnv reads "file:" secrets. Values are never logged.
func (c Config) ResolvedEnv() (map[string]string, error) {
	out := map[string]string{}
	for k, v := range c.Env {
		if path, ok := strings.CutPrefix(v, "file:"); ok {
			data, err := os.ReadFile(system.ExpandHome(path))
			if err != nil {
				return nil, fmt.Errorf("env %s: %w", k, err)
			}
			v = strings.TrimRight(string(data), "\r\n")
		}
		if strings.ContainsAny(v, "\x00\n") {
			return nil, fmt.Errorf("env %s: value must be one line", k)
		}
		out[k] = v
	}
	return out, nil
}

// Save writes the config back (used when you save a proposed command).
func Save(c Config) error {
	if err := c.validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(Path()), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	tmp := Path() + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, Path())
}

// ForGuest is what a VM needs from the host's config, with secrets resolved
// (written into the VM's own protected config dir).
func (c Config) ForGuest() (Config, error) {
	env, err := c.ResolvedEnv()
	if err != nil {
		return Config{}, err
	}
	for _, name := range c.PassEnv {
		if !ValidPassEnv(name) {
			return Config{}, fmt.Errorf("bad passEnv name %q", name)
		}
		// Transfer explicitly selected host variables through the protected
		// config stream, never argv. Configured env values take precedence.
		if _, configured := env[name]; !configured {
			if value, ok := os.LookupEnv(name); ok {
				env[name] = value
			}
		}
	}
	return Config{Backend: "native", Landlock: c.Landlock, LocalPorts: c.LocalPorts, Env: env, PassEnv: c.PassEnv, Overlays: c.Overlays}, nil
}
