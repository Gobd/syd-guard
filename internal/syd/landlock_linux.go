//go:build linux && (amd64 || arm64)

package syd

import (
	"fmt"
	"syscall"
)

// ABI 3 is required for truncate in the strict file access mapping. This is
// only a kernel availability gate; Syd must still successfully install rules.
func strictLandlockGate() error {
	const landlockCreateRuleset = 444
	const landlockCreateRulesetVersion = 1
	abi, _, errno := syscall.Syscall(landlockCreateRuleset, 0, 0, landlockCreateRulesetVersion)
	return validateStrictLandlockABI(abi, errno)
}

func validateStrictLandlockABI(abi uintptr, errno syscall.Errno) error {
	if errno != 0 {
		return fmt.Errorf("strict replay requires enabled Landlock ABI 3 or newer: %w", errno)
	}
	if abi < 3 {
		return fmt.Errorf("strict replay requires Landlock ABI 3 or newer (found %d)", abi)
	}
	return nil
}
