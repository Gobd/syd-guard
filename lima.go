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

func isMac() bool { return runtime.GOOS == "darwin" }

// limaMain runs on macOS: make sure the VM is up and has the matching Linux
// sydguard, make sure the Mac UI is up, then run the command inside the VM.
func limaMain(o opts) int {
	if _, err := exec.LookPath("limactl"); err != nil {
		return fail(fmt.Errorf("limactl not found (brew install lima)"))
	}
	if o.command == "ui" {
		return openUI(true)
	}
	vm := o.vm
	if vm == "" && o.limaFile != "" {
		vm = strings.TrimSuffix(filepath.Base(o.limaFile), filepath.Ext(o.limaFile))
	}
	if vm == "" {
		vm = envOr("SYDGUARD_VM", defaultVM)
	}
	if err := safeText(vm); err != nil || strings.ContainsAny(vm, "/ ") {
		return fail(fmt.Errorf("bad VM name %q", vm))
	}
	limaFile := o.limaFile
	if limaFile == "" {
		limaFile = os.Getenv("SYDGUARD_LIMA")
	}
	if err := ensureVM(vm, limaFile); err != nil {
		return fail(err)
	}
	if err := ensureGuestBinary(vm); err != nil {
		return fail(err)
	}
	if o.command == "doctor" {
		return fail(syscall.Exec(mustLimactl(), []string{"limactl", "shell", vm, "sydguard", "doctor"}, os.Environ()))
	}
	cwd, _ := os.Getwd()
	guestCwd, err := guestPath(vm, cwd)
	if err != nil {
		return fail(err)
	}
	argv := []string{"limactl", "shell", "--workdir", guestCwd, vm, "sydguard", "--from-mac"}
	if o.learn {
		argv = append(argv, "--learn")
	}
	if o.rules != "" {
		spec := o.rules
		if strings.ContainsRune(spec, '/') || strings.HasSuffix(spec, ".json") {
			abs := expandHome(spec)
			if !filepath.IsAbs(abs) {
				abs = filepath.Join(cwd, abs)
			}
			if spec, err = guestPath(vm, abs); err != nil {
				return fail(err)
			}
		}
		argv = append(argv, "--rules", spec)
	}
	// Start the guest daemon first so the Mac UI can connect right away.
	if out, err := exec.Command("limactl", "shell", vm, "sh", "-c", "~/.local/bin/sydguard daemon-ensure").CombinedOutput(); err != nil {
		return fail(fmt.Errorf("starting sydguard in %s: %v: %s", vm, err, out))
	}
	openUI(false)
	argv = append(append(argv, "--"), o.args...)
	return fail(syscall.Exec(mustLimactl(), argv, os.Environ()))
}

func mustLimactl() string { p, _ := exec.LookPath("limactl"); return p }

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func ensureVM(vm, file string) error {
	out, err := exec.Command("limactl", "list", "--format", "{{.Status}}", vm).Output()
	status := strings.TrimSpace(string(out))
	switch {
	case err == nil && status == "Running":
		return nil
	case err == nil && status != "":
		fmt.Fprintf(os.Stderr, "sydguard: starting Lima VM %s…\n", vm)
		return run("limactl", "start", "--tty=false", vm)
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
		fmt.Fprintf(os.Stderr, "sydguard: creating Lima VM %s from the built-in default (first boot builds Syd, ~15 min)…\n", vm)
	} else {
		fmt.Fprintf(os.Stderr, "sydguard: creating Lima VM %s from %s…\n", vm, file)
	}
	return run("limactl", "start", "--tty=false", "--name="+vm, file)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

// ensureGuestBinary copies bin/sydguard-linux-<arch> (built next to this
// binary) into the VM when the guest copy differs.
func ensureGuestBinary(vm string) error {
	arch, _ := exec.Command("limactl", "list", "--format", "{{.Arch}}", vm).Output()
	goarch := map[string]string{"aarch64": "arm64", "x86_64": "amd64"}[strings.TrimSpace(string(arch))]
	exe, _ := os.Executable()
	local := filepath.Join(filepath.Dir(exe), "sydguard-linux-"+goarch)
	if _, err := os.Stat(local); err != nil {
		return fmt.Errorf("missing %s (run make)", local)
	}
	got, _ := exec.Command("limactl", "shell", vm, "sh", "-c", "~/.local/bin/sydguard version 2>/dev/null").Output()
	if strings.TrimSpace(string(got)) == fileHash(local) {
		return nil
	}
	fmt.Fprintln(os.Stderr, "sydguard: installing sydguard into", vm)
	if err := run("limactl", "copy", local, vm+":/tmp/sydguard.new"); err != nil {
		return err
	}
	return run("limactl", "shell", vm, "sh", "-c", "mkdir -p ~/.local/bin && chmod 755 /tmp/sydguard.new && mv /tmp/sydguard.new ~/.local/bin/sydguard")
}

// guestPath maps a Mac path into the VM using its mounts.
func guestPath(vm, p string) (string, error) {
	out, err := exec.Command("limactl", "list", "--format", "{{json .Config.Mounts}}", vm).Output()
	if err != nil {
		return "", err
	}
	var mounts []struct{ Location, MountPoint string }
	if err := json.Unmarshal(out, &mounts); err != nil {
		return "", err
	}
	best, bestLen := "", -1
	for _, m := range mounts {
		loc := expandHome(m.Location)
		if under(p, loc) && len(loc) > bestLen {
			mp := m.MountPoint
			if mp == "" {
				mp = loc
			}
			best, bestLen = mp+strings.TrimPrefix(p, loc), len(loc)
		}
	}
	if bestLen < 0 {
		return "", fmt.Errorf("%s is not mounted in VM %s", p, vm)
	}
	return best, nil
}

// openUI makes sure the Mac UI server runs; opens the browser when asked or
// when the server was just started.
func openUI(always bool) int {
	started, err := ensureUIServer()
	if err != nil {
		return fail(err)
	}
	token, err := uiToken()
	if err != nil {
		return fail(err)
	}
	if always || started {
		fmt.Fprintf(os.Stderr, "sydguard: approvals UI at http://127.0.0.1:%d\n", uiPort())
		openBrowser(uiURL(token))
	}
	return 0
}
