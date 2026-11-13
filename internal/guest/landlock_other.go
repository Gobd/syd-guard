//go:build !linux

package guest

import "errors"

func checkLandlock() error { return errors.New("optional Landlock requires Linux") }
