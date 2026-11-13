// Package system holds small helpers shared by every part of sydguard:
// well-known paths, input validation, version and process utilities.
package system

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"unicode"
)

func Home() string { h, _ := os.UserHomeDir(); return h }

// ConfigDir holds rules sydguard owns (global rules, trust records).
func ConfigDir() string { return filepath.Join(Home(), ".config", "sydguard") }

// StateDir holds runtime state (sockets, sessions, logs, UI token).
func StateDir() string { return filepath.Join(Home(), ".local", "state", "sydguard") }

func DaemonSocket() string    { return filepath.Join(StateDir(), "daemon.sock") }
func GlobalRulesPath() string { return filepath.Join(ConfigDir(), "global.json") }

func IsMac() bool { return runtime.GOOS == "darwin" }

func ExpandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		return Home() + p[1:]
	}
	return p
}

// Under reports whether p is dir or inside it.
func Under(p, dir string) bool {
	return p == dir || dir == "/" || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// SafeText rejects anything that could break out of a single Syd command line.
func SafeText(s string) error {
	if s == "" || len(s) > 4096 || strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || r == unicode.ReplacementChar }) >= 0 {
		return fmt.Errorf("invalid text %q", s)
	}
	return nil
}

// SafePath is SafeText plus: absolute, no "..".
func SafePath(p string) error {
	if err := SafeText(p); err != nil {
		return err
	}
	if !filepath.IsAbs(p) || slices.Contains(strings.Split(p, "/"), "..") {
		return fmt.Errorf("path must be absolute without '..': %q", p)
	}
	return nil
}

func NewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func Alive(pid int) bool { return pid > 0 && syscall.Kill(pid, 0) == nil }

// SpawnDetached starts this binary with args in its own session, logging to logPath.
func SpawnDetached(logPath string, args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = logf.Close() }()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer func() { _ = devnull.Close() }()
	cmd := exec.Command(exe, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

var versionOnce = sync.OnceValue(func() string {
	exe, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	return FileHash(exe)
})

// Version is a hash of this binary, so daemons restart after any rebuild.
// Call it early, before an upgrade can replace the file.
func Version() string { return versionOnce() }

func FileHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	_, _ = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func HashBytes(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
