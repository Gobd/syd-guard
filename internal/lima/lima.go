// Package lima runs agents in a Lima VM: it makes sure the VM is running with the
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

	"github.com/Gobd/syd-guard/internal/config"
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

// WithDefaults fills VM and Lima file from $SYDGUARD_VM/$SYDGUARD_LIMA, then
// the config file. Flags win.
func (o Options) WithDefaults(cfg config.Config) Options {
	if o.VM == "" {
		o.VM = envOr("SYDGUARD_VM", cfg.VM)
	}
	if o.LimaFile == "" {
		o.LimaFile = system.ExpandHome(envOr("SYDGUARD_LIMA", cfg.Lima))
	}
	return o
}

// Use reports whether commands should run in a Lima VM: always when this
// machine can't run Syd itself, otherwise only when a VM or Lima file was
// chosen (flag, env or config).
func Use(o Options) bool {
	if !system.RunsSyd() {
		return true
	}
	cfg, _ := config.Load()
	o = o.WithDefaults(cfg)
	return o.VM != "" || o.LimaFile != ""
}

// VMName picks the instance: --vm, else the Lima file's name, else ai-sandbox.
func (o Options) VMName() (string, error) {
	vm := o.VM
	if vm == "" && o.LimaFile != "" {
		vm = strings.TrimSuffix(filepath.Base(o.LimaFile), filepath.Ext(o.LimaFile))
	}
	if vm == "" {
		vm = DefaultVM
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

// Prepare gets a VM ready to run agents without running one: VM up, matching
// Linux sydguard, working engine, config synced, daemon and UI running.
// `sydguard vm start` and `sydguard vm` use it.
func Prepare(o Options) (string, error) {
	if _, err := exec.LookPath("limactl"); err != nil {
		return "", errors.New("limactl not found (brew install lima)")
	}
	cfg, err := config.Load()
	if err != nil {
		return "", err
	}
	o = o.WithDefaults(cfg)
	vm, err := o.VMName()
	if err != nil {
		return "", err
	}
	if err := ensureVM(vm, o.LimaFile); err != nil {
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
	if err := syncConfig(vm, cfg); err != nil {
		return "", err
	}
	// Start the guest daemon first so the UI can connect right away.
	if out, err := exec.Command("limactl", "shell", vm, "sh", "-c", "~/.local/bin/sydguard daemon-ensure").CombinedOutput(); err != nil {
		return "", fmt.Errorf("starting sydguard in %s: %v: %s", vm, err, out)
	}
	if err := OpenUI(false); err != nil {
		fmt.Fprintln(os.Stderr, "sydguard: UI:", err)
	}
	return vm, nil
}

// syncConfig writes the parts of this machine's config the VM needs (local
// ports, overlays, secrets resolved from their files) into the VM's own
// protected config dir, via stdin (never on a command line).
func syncConfig(vm string, cfg config.Config) error {
	guest, err := cfg.ForGuest()
	if err != nil {
		return err
	}
	data, _ := json.Marshal(guest)
	cmd := exec.Command("limactl", "shell", vm, "sh", "-c",
		`umask 077 && mkdir -p ~/.config/sydguard && cat > ~/.config/sydguard/config.json.tmp && mv ~/.config/sydguard/config.json.tmp ~/.config/sydguard/config.json`)
	cmd.Stdin = strings.NewReader(string(data))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("syncing config into %s: %v: %s", vm, err, out)
	}
	return nil
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
	argv := []string{"limactl", "shell", "--workdir", guestCwd, vm, "sydguard"}
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
	argv = append(append(argv, "--"), o.Args...)
	limactl, _ := exec.LookPath("limactl")
	return syscall.Exec(limactl, argv, os.Environ())
}

// Outside runs a command in the VM *outside* the sandbox, at the same project
// path (a login shell when args is empty): for logging in to agents, or for
// trusted wrappers that then call sydguard inside the VM themselves.
func Outside(o Options, args []string) error {
	vm, err := Prepare(o)
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	argv := []string{"limactl", "shell"}
	if guestCwd, err := guestPath(vm, cwd); err == nil {
		argv = append(argv, "--workdir", guestCwd)
	}
	argv = append(argv, vm)
	if len(args) > 0 {
		argv = append(append(argv, "--"), args...)
	}
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

// OpenUI makes sure the UI server runs; opens the browser when asked or
// when the server was just started.
func OpenUI(always bool) error {
	started, err := ui.EnsureServer()
	if err != nil {
		return err
	}
	if always || started {
		fmt.Fprintln(os.Stderr, "sydguard: approvals UI at", ui.URL())
		ui.OpenBrowser(ui.URL())
	}
	return nil
}
