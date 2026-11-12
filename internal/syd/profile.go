// Package syd translates narrowly scoped launcher intent into upstream profiles.
// It does not implement syscall enforcement.
package syd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Profile builds an immutable, no-network foreground baseline. Filesystem-kind,
// syscall-path and Landlock permissions are distinct and must agree.
func Profile(workdir, temporary string, protected []string) (string, error) {
	workdir, err := canonicalDirectory(workdir)
	if err != nil {
		return "", err
	}
	temporary, err = canonicalDirectory(temporary)
	if err != nil {
		return "", err
	}
	if workdir == "/" || workdir == "/tmp" || workdir == "/private/tmp" || workdir == "/home" || workdir == "/Users" {
		return "", fmt.Errorf("working directory is too broad")
	}
	if home, err := os.UserHomeDir(); err == nil {
		if real, err := filepath.EvalSymlinks(home); err == nil && workdir == real {
			return "", fmt.Errorf("refusing writable whole-home workspace")
		}
	}
	lines := []string{"# Generated immutable Syd Guard baseline; no network grants.", "include_profile fs", "trace/force_umask:7077", "allow/create+!pipe", "allow/stat+/proc/self/fd/pipe:*", "allow/ioctl+TCGETS", "allow/ioctl+TCSETS", "allow/ioctl+TCSETSW", "allow/ioctl+TCSETSF", "allow/ioctl+TIOCGWINSZ"}
	for _, path := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"} {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return "", err
		}
		lines = append(lines, "allow/read,stat,readdir,readlink,chdir,exec+"+path+"/***", "allow/lock/read,readdir,exec+"+path)
	}
	lines = append(lines, "allow/read,stat,readdir,readlink,chdir+/etc/***", "allow/lock/read,readdir+/etc")
	for _, path := range []string{"/dev/null", "/dev/random", "/dev/urandom"} {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return "", err
		}
		lines = append(lines, "allow/read,stat+"+path, "allow/lock/read+"+path)
	}
	lines = append(lines, "allow/write+/dev/null", "allow/lock/write+/dev/null")
	for _, path := range []string{workdir, temporary} {
		// Explicit operation list: no implicit socket/network/ioctl grants.
		lines = append(lines,
			"allow/read,stat,readdir,readlink,chdir,write,create,delete,rename,truncate,chmod,chattr,mkdir,rmdir,symlink,exec+"+path+"/***",
			"allow/read,stat,readdir,readlink,chdir+"+path,
			"allow/lock/read,readdir,write,create,delete,rename,truncate,mkdir,rmdir,symlink,exec+"+path)
	}
	rules, err := ProtectedRules(workdir, protected)
	if err != nil {
		return "", err
	}
	lines = append(lines, strings.TrimSuffix(rules, "\n"))
	// No lock:off, live IPC, user preset, unsafe options, or network grants.
	// Upstream's default auto-seals after parsing. Test /dev/syd mutation denial.
	return strings.Join(lines, "\n") + "\n", nil
}

func canonicalDirectory(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if err := literalPath(path); err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("not a directory: %s", path)
	}
	return path, nil
}

func literalPath(path string) error {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n*?[]{}\\$;!") {
		return fmt.Errorf("path cannot be safely represented as a literal Syd rule: %q", path)
	}
	return nil
}
