// Package config manages private operator settings, not project permission policy.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Gobd/syd-guard/internal/backend"
)

type Lima struct {
	Instance     string `json:"instance"`
	ConfigPath   string `json:"config_path"`
	ConfigSHA256 string `json:"config_sha256,omitempty"`
}

type Settings struct {
	Version int          `json:"version"`
	Backend backend.Kind `json:"backend"`
	Lima    Lima         `json:"lima"`
}

func Path() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "sydguard", "config.json"), nil
}

func Default() (Settings, error) {
	path, err := Path()
	if err != nil {
		return Settings{}, err
	}
	return Settings{Version: 1, Backend: backend.Auto, Lima: Lima{Instance: "ai-sandbox", ConfigPath: filepath.Join(filepath.Dir(path), "lima.yaml")}}, nil
}

func Load() (Settings, error) {
	settings, err := Default()
	if err != nil {
		return Settings{}, err
	}
	path, err := Path()
	if err != nil {
		return Settings{}, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return settings, nil
	}
	if err != nil {
		return Settings{}, err
	}
	if err := privateFile(info); err != nil {
		return Settings{}, err
	}
	if info.Size() > 1024*1024 {
		return Settings{}, fmt.Errorf("operator config is too large")
	}
	data, err := os.ReadFile(path) //nolint:gosec // validated private operator config, never an auto-discovered project file
	if err != nil {
		return Settings{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&settings); err != nil {
		return Settings{}, fmt.Errorf("invalid operator config: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return Settings{}, fmt.Errorf("operator config contains trailing data")
	}
	return settings, settings.Validate()
}

func (s Settings) Validate() error {
	if s.Version != 1 {
		return fmt.Errorf("unsupported operator config version %d", s.Version)
	}
	if s.Backend != backend.Auto && s.Backend != backend.Native && s.Backend != backend.Lima {
		return fmt.Errorf("invalid configured backend %q", s.Backend)
	}
	if s.Lima.Instance == "" || !filepath.IsAbs(s.Lima.ConfigPath) {
		return fmt.Errorf("Lima requires an instance and absolute config path")
	}
	if s.Lima.ConfigSHA256 != "" {
		decoded, err := hex.DecodeString(s.Lima.ConfigSHA256)
		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("invalid Lima recipe fingerprint")
		}
	}
	return nil
}

func Save(s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	path, err := Path()
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("operator config directory must be a private real directory")
	}
	if err := checkOwner(info); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if err := privateFile(info); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".config-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func privateFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("operator config must be a private regular file, not a symlink")
	}
	return checkOwner(info)
}

func ResolveRecipe(path string) (string, string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", err
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	if strings.ContainsAny(path, "\x00\r\n") {
		return "", "", fmt.Errorf("invalid recipe path")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 4*1024*1024 {
		return "", "", fmt.Errorf("Lima recipe must be a regular file under 4 MiB")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	hash := sha256.Sum256(data)
	return path, hex.EncodeToString(hash[:]), nil
}
