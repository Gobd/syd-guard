//go:build linux && (amd64 || arm64)

package syd

import (
	"syscall"
	"testing"
)

func TestStrictLandlockABI(t *testing.T) {
	abi, _, errno := syscall.Syscall(444, 0, 0, 1)
	t.Logf("host Landlock ABI=%d errno=%v", abi, errno)
	for _, tc := range []struct {
		abi     uintptr
		errno   syscall.Errno
		allowed bool
	}{
		{0, syscall.ENOSYS, false},
		{0, syscall.EOPNOTSUPP, false},
		{0, syscall.EPERM, false},
		{1, 0, false},
		{2, 0, false},
		{3, 0, true},
		{6, 0, true},
	} {
		if (validateStrictLandlockABI(tc.abi, tc.errno) == nil) != tc.allowed {
			t.Errorf("abi=%d errno=%v", tc.abi, tc.errno)
		}
	}
}
