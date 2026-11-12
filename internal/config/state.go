package config

import "path/filepath"

// PrivateAuthorityFolder is a reserved, globally protected path component.
// Credentials placed here remain excluded even when another launcher selects
// a different XDG configuration. It is not a general secret classifier.
const PrivateAuthorityFolder = ".sydguard-private"

// StateDirectory shares the protected operator tree, not a writable project or
// a possibly group-writable ~/.local/state ancestor.
func StateDirectory() (string, error) {
	path, err := Path()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "state"), nil
}
