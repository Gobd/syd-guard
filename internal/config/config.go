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

	"github.com/Gobd/syd-guard/internal/system"
)

type Config struct {
	VM         string            `json:"vm,omitempty"`         // Lima instance (macOS)
	Lima       string            `json:"lima,omitempty"`       // Lima file to create it from (macOS)
	LocalPorts []int             `json:"localPorts,omitempty"` // like --local-port, for every run
	Env        map[string]string `json:"env,omitempty"`        // NAME: "value" or "file:PATH" (secret file)
	Overlays   []string          `json:"overlays,omitempty"`   // build folders kept on the VM disk
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
	for _, p := range c.LocalPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("%s: bad local port %d", Path(), p)
		}
	}
	for k := range c.Env {
		if !envName.MatchString(k) || strings.HasPrefix(k, "SYD_") {
			return fmt.Errorf("%s: bad env name %q", Path(), k)
		}
	}
	for _, o := range c.Overlays {
		if o == "" || strings.ContainsAny(o, "/:") || o == "." || o == ".." || o == ".git" {
			return fmt.Errorf("%s: overlay must be a plain folder name, got %q", Path(), o)
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

// ForGuest is what a VM needs from the host's config, with secrets resolved
// (written into the VM's own protected config dir).
func (c Config) ForGuest() (Config, error) {
	env, err := c.ResolvedEnv()
	if err != nil {
		return Config{}, err
	}
	return Config{LocalPorts: c.LocalPorts, Env: env, Overlays: c.Overlays}, nil
}
