package lima

import (
	"fmt"
	"path"
	"strings"
)

// GuestCommand builds structured argv; configuration paths are not credentials.
func GuestCommand(executable, configHome string, args []string) ([]string, error) {
	if executable == "" {
		executable = "sydguard"
	} else if !safeGuestPath(executable) {
		return nil, fmt.Errorf("--guest-sydguard must be a clean absolute guest executable path")
	}
	if configHome != "" && !safeGuestPath(configHome) {
		return nil, fmt.Errorf("--guest-config-home must be a clean absolute guest directory")
	}
	command := []string{executable}
	if configHome != "" {
		command = []string{"/usr/bin/env", "XDG_CONFIG_HOME=" + configHome, executable}
	}
	return append(command, args...), nil
}

func safeGuestPath(p string) bool {
	return path.IsAbs(p) && path.Clean(p) == p && p != "/" && !strings.ContainsAny(p, "\x00\r\n")
}
