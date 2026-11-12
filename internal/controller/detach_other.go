//go:build !linux && !darwin

package controller

import "os/exec"

func detach(_ *exec.Cmd) {}
