package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProjectDirectory stores reviewed operator policy outside the writable checkout.
// Canonical project path identifies the policy, never its friendly session label.
func ProjectDirectory(project string) (string, error) {
	if !filepath.IsAbs(project) {
		return "", fmt.Errorf("project path must be absolute")
	}
	project, err := filepath.EvalSymlinks(project)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(project)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("project must be an existing directory")
	}
	if strings.ContainsAny(project, "\x00\r\n") {
		return "", fmt.Errorf("invalid project path")
	}
	state, err := StateDirectory()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(project))
	directory := filepath.Join(state, "projects", hex.EncodeToString(digest[:]))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	for _, path := range []string{state, filepath.Join(state, "projects"), directory} {
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("unsafe protected project-policy directory")
		}
		if err := checkOwner(info); err != nil {
			return "", err
		}
	}
	identity, err := json.Marshal(struct {
		Version int    `json:"version"`
		Project string `json:"project"`
	}{1, project})
	if err != nil {
		return "", err
	}
	file, err := os.OpenFile(filepath.Join(directory, "project.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // fixed identity filename within validated operator-owned directory, exclusive create
	if err == nil {
		_, writeErr := file.Write(identity)
		closeErr := file.Close()
		if writeErr != nil {
			return "", writeErr
		}
		if closeErr != nil {
			return "", closeErr
		}
	} else if !os.IsExist(err) {
		return "", err
	}
	return directory, nil
}
