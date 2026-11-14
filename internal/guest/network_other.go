//go:build !linux

package guest

import (
	"errors"
	"os/exec"
)

func (d *Daemon) startNetwork(*Session) error { return errors.New("session networking requires Linux") }
func protectNetworkCommand(*exec.Cmd)         {}
func NetworkRun(string, []string) error       { return errors.New("session networking requires Linux") }

func NetworkOwner(string, []string) error { return errors.New("session networking requires Linux") }
