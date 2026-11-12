// Package lima contains the optional host adapter. Native Linux does not need it.
package lima

import (
	"fmt"
	"regexp"
)

var instanceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

// ShellArgs keeps command arguments separate; names never become shell code.
func ShellArgs(instance string, command []string) ([]string, error) {
	if !instanceName.MatchString(instance) {
		return nil, fmt.Errorf("invalid Lima instance name %q", instance)
	}
	if len(command) == 0 || command[0] == "" {
		return nil, fmt.Errorf("missing guest command")
	}
	args := []string{"shell", "--workdir", "/tmp", instance}
	return append(args, command...), nil
}
