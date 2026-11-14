//go:build !linux

package guest

import "errors"

func OverlayMount(int, string, string) error { return errors.New("overlays need Linux") }

func mountedIn(int, string) bool { return false }

func hostShares() []string { return nil }
