// Package lima is the macOS side: it makes sure a Lima VM is running with the
// matching Linux sydguard and a working Syd, then runs commands inside it at
// the same project path.
package lima

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Gobd/syd-guard/internal/system"
	"github.com/Gobd/syd-guard/internal/ui"
)

//go:embed default.yaml
var defaultYAML []byte

const DefaultVM = "ai-sandbox"

type Options struct {
	VM, LimaFile, Rules string
	Learn               bool
	LocalPorts          []int
	Args                []string
}

// VMName picks the instance: --vm, else the Lima file's name, else
// $SYDGUARD_VM, else ai-sandbox.
func (o Options) VMName() (string, error) {
	vm := o.VM
	if vm == "" && o.LimaFile != "" {
		vm = strings.TrimSuffix(filepath.Base(o.LimaFile), filepath.Ext(o.LimaFile))
	}
	if vm == "" {
		vm = envOr("SYDGUARD_VM", DefaultVM)
	}
	if err := system.SafeText(vm); err != nil || strings.ContainsAny(vm, "/ ") {
		return "", fmt.Errorf("bad VM name %q", vm)
	}
	return vm, nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// Prepare makes sure the VM runs, has our Linux binary and a working engine.
func Prepare(o Options) (string, error) {
	if _, err := exec.LookPath("limactl"); err != nil {
		return "", errors.New("limactl not found (brew install lima)")
	}
	vm, err := o.VMName()
	if err != nil {
		return "", err
	}
	file := o.LimaFile
	if file == "" {
		file = os.Getenv("SYDGUARD_LIMA")
	}
	if err := ensureVM(vm, file); err != nil {
		return "", err
	}
	if err := ensureGuestBinary(vm); err != nil {
		return "", err
	}
	if exec.Command("limactl", "shell", vm, "sh", "-c", "~/.local/bin/sydguard engine-check >/dev/null 2>&1").Run() != nil {
		fmt.Fprintf(os.Stderr, "sydguard: installing the Syd engine in %s (one time; builds from source, ~10 min)…\n", vm)
		if err := run("limactl", "shell", vm, "sh", "-c", "~/.local/bin/sydguard setup"); err != nil {
			return "", fmt.Errorf("setup in %s failed: %w", vm, err)
		}
	}
	return vm, nil
}

// Run runs the command inside the VM under sydguard. It only returns on error.
func Run(o Options) error {
	vm, err := Prepare(o)
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	guestCwd, err := guestPath(vm, cwd)
	if err != nil {
		return err
	}
	argv := []string{"limactl", "shell", "--workdir", guestCwd, vm, "sydguard", "--from-mac"}
	if o.Learn {
		argv = append(argv, "--learn")
	}
	for _, p := range o.LocalPorts {
		argv = append(argv, "--local-port", strconv.Itoa(p))
	}
	if o.Rules != "" {
		spec := o.Rules
		if strings.ContainsRune(spec, '/') || strings.HasSuffix(spec, ".json") {
			abs := system.ExpandHome(spec)
			if !filepath.IsAbs(abs) {
				abs = filepath.Join(cwd, abs)
			}
			if spec, err = guestPath(vm, abs); err != nil {
				return err
			}
		}
		argv = append(argv, "--rules", spec)
	}
	// Start the guest daemon first so the Mac UI can connect right away.
	if out, err := exec.Command("limactl", "shell", vm, "sh", "-c", "~/.local/bin/sydguard daemon-ensure").CombinedOutput(); err != nil {
		return fmt.Errorf("starting sydguard in %s: %v: %s", vm, err, out)
	}
	if err := OpenUI(false); err != nil {
		fmt.Fprintln(os.Stderr, "sydguard: UI:", err)
	}
	argv = append(append(argv, "--"), o.Args...)
	limactl, _ := exec.LookPath("limactl")
	return syscall.Exec(limactl, argv, os.Environ())
}

// Shell runs a guest command (doctor, setup) in the VM, replacing this process.
func Shell(o Options, args ...string) error {
	vm, err := Prepare(o)
	if err != nil {
		return err
	}
	limactl, _ := exec.LookPath("limactl")
	return syscall.Exec(limactl, append([]string{"limactl", "shell", vm, "sydguard"}, args...), os.Environ())
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
		_, _ = f.Write(defaultYAML)
		_ = f.Close()
		file = f.Name()
		fmt.Fprintf(os.Stderr, "sydguard: creating Lima VM %s from the built-in default…\n", vm)
	} else {
		fmt.Fprintf(os.Stderr, "sydguard: creating Lima VM %s from %s…\n", vm, file)
	}
	return run("limactl", "start", "--tty=false", "--name="+vm, file)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	return cmd.Run()
}

// ensureGuestBinary copies sydguard-linux-<arch> (built next to this binary)
// into the VM when the guest copy differs.
func ensureGuestBinary(vm string) error {
	arch, _ := exec.Command("limactl", "list", "--format", "{{.Arch}}", vm).Output()
	goarch := map[string]string{"aarch64": "arm64", "x86_64": "amd64"}[strings.TrimSpace(string(arch))]
	exe, _ := os.Executable()
	local := filepath.Join(filepath.Dir(exe), "sydguard-linux-"+goarch)
	if _, err := os.Stat(local); err != nil {
		return fmt.Errorf("missing %s (run make)", local)
	}
	got, _ := exec.Command("limactl", "shell", vm, "sh", "-c", "~/.local/bin/sydguard version 2>/dev/null").Output()
	if strings.TrimSpace(string(got)) == system.FileHash(local) {
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
		loc := system.ExpandHome(m.Location)
		if system.Under(p, loc) && len(loc) > bestLen {
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

// OpenUI makes sure the Mac UI server runs; opens the browser when asked or
// when the server was just started.
func OpenUI(always bool) error {
	started, err := ui.EnsureServer()
	if err != nil {
		return err
	}
	token, err := ui.Token()
	if err != nil {
		return err
	}
	if always || started {
		fmt.Fprintln(os.Stderr, "sydguard: approvals UI at http://127.0.0.1:7878")
		ui.OpenBrowser(ui.URL(token))
	}
	return nil
}
