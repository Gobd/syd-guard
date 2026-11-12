// Package backend selects the Linux execution environment without pretending
// that the Syd enforcement engine can run natively on macOS or Windows.
package backend

import "fmt"

type Kind string

const (
	Auto   Kind = "auto"
	Native Kind = "native"
	Lima   Kind = "lima"
)

func Select(goos string, requested Kind) (Kind, error) {
	if requested != Auto && requested != Native && requested != Lima {
		return "", fmt.Errorf("unknown backend %q (use auto, native or lima)", requested)
	}
	if goos == "windows" {
		return "", fmt.Errorf("run the Linux CLI inside current WSL; a native Windows adapter is not implemented")
	}
	if requested == Native && goos != "linux" {
		return "", fmt.Errorf("native Syd requires Linux; use the Lima backend on macOS")
	}
	if requested != Auto {
		return requested, nil
	}
	switch goos {
	case "linux":
		return Native, nil
	case "darwin":
		return Lima, nil
	default:
		return "", fmt.Errorf("unsupported platform %q", goos)
	}
}
