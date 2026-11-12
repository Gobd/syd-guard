//go:build !linux && !darwin

package controller

import (
	"fmt"
	"os"
)

func owned(_ os.FileInfo) error { return fmt.Errorf("run the controller inside Linux/WSL") }
func lockController(_ string) (*os.File, error) {
	return nil, fmt.Errorf("run the controller inside Linux/WSL")
}
