//go:build !linux || (!amd64 && !arm64)

package syd

import "fmt"

func strictLandlockGate() error {
	return fmt.Errorf("strict replay requires supported Linux amd64 or arm64 with Landlock ABI 3 or newer")
}
