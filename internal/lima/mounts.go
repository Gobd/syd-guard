package lima

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

type Mount struct {
	Location   string `json:"location"`
	MountPoint string `json:"mountPoint"`
}

// MapDirectory uses the longest component-boundary match from the selected
// instance's reported mount configuration; it never creates or changes mounts.
func MapDirectory(directory string, mounts []Mount) (string, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return "", fmt.Errorf("host working directory must be clean and absolute")
	}
	best, target := "", ""
	for _, m := range mounts {
		if !filepath.IsAbs(m.Location) || filepath.Clean(m.Location) != m.Location || !filepath.IsAbs(m.MountPoint) || filepath.Clean(m.MountPoint) != m.MountPoint {
			continue
		}
		if (directory == m.Location || strings.HasPrefix(directory, strings.TrimSuffix(m.Location, "/")+"/")) && len(m.Location) > len(best) {
			best, target = m.Location, m.MountPoint
		}
	}
	if best == "" {
		return "", fmt.Errorf("working directory %s is not mapped into the selected Lima instance; use --directory with an existing guest path", directory)
	}
	rel, err := filepath.Rel(best, directory)
	if err != nil {
		return "", err
	}
	return filepath.Join(target, rel), nil
}

func InstanceMounts(ctx context.Context, instance string) ([]Mount, error) {
	if !instanceName.MatchString(instance) {
		return nil, fmt.Errorf("invalid Lima instance name")
	}
	command := exec.CommandContext(ctx, "limactl", "list", "--json", instance) //nolint:gosec // validated instance name, fixed direct argv
	var output bytes.Buffer
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("lima mount lookup: %w", err)
	}
	if output.Len() > 1024*1024 {
		return nil, fmt.Errorf("lima instance metadata too large")
	}
	var value struct {
		Name   string `json:"name"`
		Config struct {
			Mounts []Mount `json:"mounts"`
		} `json:"config"`
	}
	if err := json.Unmarshal(output.Bytes(), &value); err != nil || value.Name != instance {
		return nil, fmt.Errorf("invalid Lima instance metadata")
	}
	return value.Config.Mounts, nil
}
