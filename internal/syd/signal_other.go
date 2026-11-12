//go:build !linux && !darwin

package syd

import "os"

func processSignal(*os.ProcessState) os.Signal { return nil }
