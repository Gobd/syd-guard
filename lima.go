package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

//go:embed default-lima.yaml
var defaultLimaYAML []byte

const defaultVM = "ai-sandbox"

// limaMain runs on macOS: make sure the VM is up and has the matching Linux
// sydguard, then run the command under sydguard inside it.
func limaMain(o opts) int {
	limactl, err := exec.LookPath("limactl")
	if err != nil {
		return fail(fmt.Errorf("limactl not found (brew install lima)"))
	}
	vm := o.vm
	if vm == "" && o.limaFile != "" {
		vm = strings.TrimSuffix(filepath.Base(o.limaFile), filepath.Ext(o.limaFile))
	}
	if vm == "" {
		vm = envOr("SYDGUARD_VM", defaultVM)
	}
	if err := ensureVM(limactl, vm, o.limaFile); err != nil {
		return fail(err)
	}
	if err := ensureGuestBinary(limactl, vm); err != nil {
		return fail(err)
	}
	if o.command == "ui" {
		return openUI(limactl, vm, true)
	}
	cwd, _ := os.Getwd()
	guestCwd, err := guestPath(limactl, vm, cwd)
	if err != nil {
		return fail(err)
	}
	openUI(limactl, vm, false) // starts the daemon; opens the browser the first time
	argv := []string{"limactl", "shell", "--workdir", guestCwd, vm, "sydguard"}
	if o.learn {
		argv = append(argv, "--learn")
	}
	argv = append(append(argv, "--"), o.args...)
	return fail(syscall.Exec(limactl, argv, os.Environ()))
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func ensureVM(limactl, vm, file string) error {
	out, err := exec.Command(limactl, "list", "--format", "{{.Status}}", vm).Output()
	status := strings.TrimSpace(string(out))
	switch {
	case err == nil && status == "Running":
		return nil
	case err == nil && status != "":
		fmt.Fprintf(os.Stderr, "sydguard: starting Lima VM %s…\n", vm)
		return run(limactl, "start", "--tty=false", vm)
	}
	if file == "" {
		f, err := os.CreateTemp("", "sydguard-*.yaml")
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(f.Name()) }()
		_, _ = f.Write(defaultLimaYAML)
		_ = f.Close()
		file = f.Name()
	}
	fmt.Fprintf(os.Stderr, "sydguard: creating Lima VM %s from %s…\n", vm, file)
	return run(limactl, "start", "--tty=false", "--name="+vm, file)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

// ensureGuestBinary copies bin/sydguard-linux-<arch> (built next to this
// binary) into the VM when the guest copy differs.
func ensureGuestBinary(limactl, vm string) error {
	arch, _ := exec.Command(limactl, "list", "--format", "{{.Arch}}", vm).Output()
	goarch := map[string]string{"aarch64": "arm64", "x86_64": "amd64"}[strings.TrimSpace(string(arch))]
	exe, _ := os.Executable()
	local := filepath.Join(filepath.Dir(exe), "sydguard-linux-"+goarch)
	if _, err := os.Stat(local); err != nil {
		return fmt.Errorf("missing %s (run make)", local)
	}
	want := fileHash(local)
	got, _ := exec.Command(limactl, "shell", vm, "sh", "-c", "~/.local/bin/sydguard version 2>/dev/null").Output()
	if strings.TrimSpace(string(got)) == want {
		return nil
	}
	fmt.Fprintln(os.Stderr, "sydguard: installing sydguard into", vm)
	if err := run(limactl, "copy", local, vm+":/tmp/sydguard.new"); err != nil {
		return err
	}
	return run(limactl, "shell", vm, "sh", "-c", "mkdir -p ~/.local/bin && chmod 755 /tmp/sydguard.new && mv /tmp/sydguard.new ~/.local/bin/sydguard")
}

// guestPath maps a Mac path into the VM using its mounts.
func guestPath(limactl, vm, cwd string) (string, error) {
	out, err := exec.Command(limactl, "list", "--format", "{{json .Config.Mounts}}", vm).Output()
	if err != nil {
		return "", err
	}
	var mounts []struct{ Location, MountPoint string }
	if err := json.Unmarshal(out, &mounts); err != nil {
		return "", err
	}
	best, bestLen := "", -1
	for _, m := range mounts {
		loc := strings.Replace(m.Location, "~", home(), 1)
		if under(cwd, loc) && len(loc) > bestLen {
			mp := m.MountPoint
			if mp == "" {
				mp = loc
			}
			best, bestLen = mp+strings.TrimPrefix(cwd, loc), len(loc)
		}
	}
	if bestLen < 0 {
		return "", fmt.Errorf("%s is not mounted in VM %s", cwd, vm)
	}
	return best, nil
}

func openUI(limactl, vm string, always bool) int {
	out, err := exec.Command(limactl, "shell", vm, "sh", "-c", "~/.local/bin/sydguard daemon-ensure").Output()
	if err != nil {
		return fail(fmt.Errorf("starting daemon in %s: %w", vm, err))
	}
	status, url, _ := strings.Cut(strings.TrimSpace(string(out)), " ")
	if always || status == "started" {
		fmt.Fprintln(os.Stderr, "sydguard: approvals UI", url)
		_ = exec.Command("open", url).Run()
	}
	return 0
}

func isMac() bool { return runtime.GOOS == "darwin" }
