package lima

import (
	"testing"

	"github.com/Gobd/syd-guard/internal/config"
)

func TestBackendSelection(t *testing.T) {
	for _, key := range []string{"SYDGUARD_BACKEND", "SYDGUARD_VM", "SYDGUARD_LIMA"} {
		t.Setenv(key, "")
	}
	for _, tc := range []struct {
		name                  string
		options               Options
		config                config.Config
		linux, guest, vm, bad bool
	}{
		{name: "Linux defaults to VM", linux: true, vm: true},
		{name: "macOS defaults to VM", vm: true},
		{name: "guest avoids recursion", linux: true, guest: true},
		{name: "explicit native", linux: true, options: Options{Backend: "native"}},
		{name: "native config", linux: true, config: config.Config{Backend: "native"}},
		{name: "flag overrides config", linux: true, vm: true, options: Options{Backend: "lima"}, config: config.Config{Backend: "native"}},
		{name: "VM selection overrides config", linux: true, vm: true, options: Options{VM: "work"}, config: config.Config{Backend: "native"}},
		{name: "explicit native overrides VM default", linux: true, options: Options{Backend: "native"}, config: config.Config{VM: "work"}},
		{name: "conflicting flags", linux: true, bad: true, options: Options{Backend: "native", VM: "work"}},
		{name: "native requires Linux", bad: true, options: Options{Backend: "native"}},
		{name: "invalid backend", linux: true, bad: true, options: Options{Backend: "typo"}},
		{name: "explicit nested VM", linux: true, guest: true, vm: true, options: Options{Backend: "lima"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vm, err := selectBackend(tc.options, tc.config, tc.linux, tc.guest)
			if (err != nil) != tc.bad || (err == nil && vm != tc.vm) {
				t.Fatalf("VM=%v err=%v", vm, err)
			}
		})
	}
	t.Setenv("SYDGUARD_BACKEND", "native")
	if vm, err := selectBackend(Options{}, config.Config{}, true, false); err != nil || vm {
		t.Fatalf("explicit environment opt-in: %v %v", vm, err)
	}
}
