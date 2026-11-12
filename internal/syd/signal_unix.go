//go:build linux || darwin

package syd

import (
	"os"
	"syscall"
)

func processSignal(state *os.ProcessState) os.Signal {
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return status.Signal()
	}
	return nil
}
