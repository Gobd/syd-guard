//go:build !linux

package session

import "fmt"

func ProcessIdentity(_ int) (string, error) {
	return "", fmt.Errorf("session start identity is obtained in the Linux controller")
}
