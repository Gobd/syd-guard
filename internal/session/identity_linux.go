//go:build linux

package session

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ProcessIdentity ties a PID to a boot and kernel start tick, rather than kill(0).
// Lifecycle signaling still needs pidfd protection; this is not a signal API.
func ProcessIdentity(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid process ID")
	}
	path := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(path) //nolint:gosec // numeric PID fixes the proc stat path; no caller-controlled file inclusion
	if err != nil {
		return "", err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	return identityFromStat(strings.TrimSpace(string(boot)), string(data))
}

func identityFromStat(boot, stat string) (string, error) {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 || boot == "" {
		return "", fmt.Errorf("invalid process stat/boot identity")
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 20 {
		return "", fmt.Errorf("truncated process stat")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return "", fmt.Errorf("invalid process start tick")
	}
	return fmt.Sprintf("%s:%d", boot, start), nil
}
