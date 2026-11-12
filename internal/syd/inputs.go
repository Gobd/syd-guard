package syd

import (
	"fmt"
	"os"
	"path/filepath"
)

// InputRules grants read or execution for explicitly selected regular files,
// never recursive access to their parent directory or write access.
func InputRules(readInputs, execInputs, protected []string) (string, error) {
	var rules string
	for _, input := range []struct {
		kind  string
		paths []string
	}{{"read", readInputs}, {"exec", execInputs}} {
		for _, name := range input.paths {
			if !filepath.IsAbs(name) {
				return "", fmt.Errorf("trusted input must be an absolute file path")
			}
			path, err := filepath.EvalSymlinks(name)
			if err != nil {
				return "", err
			}
			if ProtectedPath(name, "read", "") || ProtectedPath(path, "read", "") {
				return "", fmt.Errorf("trusted input matches protected preset")
			}
			if err := literalPath(path); err != nil {
				return "", err
			}
			info, err := os.Stat(path)
			if err != nil {
				return "", err
			}
			if !info.Mode().IsRegular() {
				return "", fmt.Errorf("trusted input must be a regular file")
			}
			for _, blocked := range protected {
				if resolved, err := filepath.EvalSymlinks(blocked); err == nil {
					blocked = resolved
				}
				if pathOverlaps(path, blocked) {
					return "", fmt.Errorf("trusted input overlaps protected authority")
				}
			}
			if input.kind == "read" {
				rules += "allow/read,stat+" + path + "\nallow/lock/read+" + path + "\n"
			} else {
				rules += "allow/read,stat,exec+" + path + "\nallow/lock/read,exec+" + path + "\n"
			}
		}
	}
	return rules, nil
}
