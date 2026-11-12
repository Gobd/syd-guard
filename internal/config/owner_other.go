//go:build !linux && !darwin

package config

import (
	"fmt"
	"os"
)

func checkOwner(_ os.FileInfo) error {
	return fmt.Errorf("private operator configuration is supported on Linux/macOS; use the Linux CLI inside WSL")
}
