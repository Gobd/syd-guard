package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// goEligibility obtains cache locations before starting the workload. These are
// Landlock ceilings only, not filesystem grants.
func goEligibility(ctx context.Context, project, state string) ([]string, error) {
	path, err := exec.LookPath("go")
	if err != nil {
		return nil, nil
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(path) || pathInside(path, project) {
		return nil, fmt.Errorf("unsafe Go executable")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("unsafe Go executable")
	}
	deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(deadline, path, "env", "-json", "GOMODCACHE", "GOCACHE", "GOBIN", "GOPATH") //nolint:gosec // resolved operator PATH executable outside the project, with fixed diagnostic argv
	command.Dir = "/"
	command.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local")
	var output boundedOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("go cache discovery: %w", err)
	}
	var values map[string]string
	if err := json.Unmarshal(output.Bytes(), &values); err != nil {
		return nil, fmt.Errorf("go cache discovery: %w", err)
	}
	bin := values["GOBIN"]
	if bin == "" && values["GOPATH"] != "" {
		bin = filepath.Join(strings.Split(values["GOPATH"], string(os.PathListSeparator))[0], "bin")
	}
	home, _ := os.UserHomeDir()
	home, _ = filepath.EvalSymlinks(home)
	var roots []string
	for _, candidate := range []string{values["GOMODCACHE"], values["GOCACHE"], bin} {
		if candidate == "" {
			continue
		}
		if !filepath.IsAbs(candidate) || filepath.Clean(candidate) != candidate {
			return nil, fmt.Errorf("invalid Go cache ceiling")
		}
		root, err := filepath.EvalSymlinks(candidate)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() || root == "/" || root == home || root == "/home" || root == "/Users" || pathInside(root, state) || pathInside(state, root) || strings.ContainsAny(root, "\x00\r\n*?[]{}\\$;!") {
			return nil, fmt.Errorf("unsafe Go cache ceiling %q", root)
		}
		roots = append(roots, root)
	}
	return roots, nil
}

func pathInside(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 64*1024 {
		return 0, fmt.Errorf("go env output too large")
	}
	return b.Buffer.Write(p)
}
