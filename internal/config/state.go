package config

import "path/filepath"

// StateDirectory shares the protected operator tree, not a writable project or
// a possibly group-writable ~/.local/state ancestor.
func StateDirectory() (string, error) {
	path, err := Path()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "state"), nil
}
