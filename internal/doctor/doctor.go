// Package doctor probes prerequisites; a successful probe is not a sandbox audit.
package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type Report struct {
	Platform     string  `json:"platform"`
	Architecture string  `json:"architecture"`
	Kernel       string  `json:"kernel"`
	SydPath      string  `json:"syd_path,omitempty"`
	Checks       []Check `json:"checks"`
	LaunchReady  bool    `json:"launch_ready"`
}

func Probe(ctx context.Context, explicit string) Report {
	r := Report{Platform: runtime.GOOS, Architecture: runtime.GOARCH, Checks: []Check{}}
	if kernel, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		r.Kernel = strings.TrimSpace(string(kernel))
	}
	if runtime.GOOS != "linux" {
		r.Checks = append(r.Checks, Check{"Linux", false, "Syd requires Linux; use Lima on macOS or run inside WSL"})
		return r
	}
	path, err := LocateSyd(explicit)
	if err != nil {
		r.Checks = append(r.Checks, Check{"Syd executable", false, err.Error()})
		return r
	}
	r.SydPath = path
	for _, option := range []string{"--version", "--check"} {
		output, err := exec.CommandContext(ctx, path, option).CombinedOutput() //nolint:gosec // explicit trusted engine executable; fixed diagnostic arguments, no shell
		detail := strings.TrimSpace(string(output))
		if err != nil {
			detail = fmt.Sprintf("%v\n%s", err, detail)
		}
		r.Checks = append(r.Checks, Check{"syd " + option, err == nil, detail})
	}
	// Full agent workflow readiness includes the not-yet-built mutable controller.
	r.Checks = append(r.Checks, Check{"full session/control-plane gate", false, "immutable no-network foreground baseline tested; learning, mutable IPC, registry and UI are not complete"})
	return r
}

func LocateSyd(explicit string) (string, error) {
	if explicit != "" {
		path, err := exec.LookPath(explicit)
		if err != nil {
			return "", fmt.Errorf("configured Syd executable: %w", err)
		}
		return path, nil
	}
	if path, err := exec.LookPath("syd"); err == nil {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(home, ".cargo", "bin", "syd")
	if found, err := exec.LookPath(path); err == nil {
		return found, nil
	}
	return "", fmt.Errorf("upstream Syd is not installed (checked PATH and %s)", path)
}
