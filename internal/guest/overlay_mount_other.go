//go:build !linux

package guest

import "errors"

func ensureOverlayDir(_ string, _ bool) error { return errors.New("overlays require Linux") }

func OverlayMount(_ int, _, _ string, _ bool) error {
	return errors.New("live overlays require Linux")
}
