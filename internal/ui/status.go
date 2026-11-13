package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Gobd/syd-guard/internal/system"
)

// ping returns the running UI server's build, "" if none answers.
func ping() string {
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get(URL() + "api/ping")
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	var p struct{ Version string }
	if json.NewDecoder(resp.Body).Decode(&p) != nil || p.Version == "" {
		return "?"
	}
	return p.Version
}

func runningMachines() ([]Machine, error) {
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(URL() + "api/state")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var st struct{ Machines []Machine }
	return st.Machines, json.NewDecoder(resp.Body).Decode(&st)
}

// guestBuilds are the Linux binaries this sydguard would install into VMs.
func guestBuilds() map[string]bool {
	exe, _ := os.Executable()
	out := map[string]bool{}
	for _, arch := range []string{"arm64", "amd64"} {
		if h := system.FileHash(filepath.Join(filepath.Dir(exe), "sydguard-linux-"+arch)); h != "" {
			out[h] = true
		}
	}
	return out
}

func pidOf(name string) string {
	b, err := os.ReadFile(system.StateDir() + "/" + name + ".pid")
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(b))
}

// Status prints the UI server, this machine's daemon and every Lima VM.
func Status() error {
	mine := system.Version()
	switch v := ping(); v {
	case "":
		fmt.Println("UI         not running (start: sydguard ui)")
	case mine:
		fmt.Printf("UI         running  %s  pid %s  build %s (current)\n", URL(), pidOf("ui"), v)
	default:
		fmt.Printf("UI         running  %s  pid %s  build %s (OUTDATED: this binary is %s; sydguard restart)\n", URL(), pidOf("ui"), v, mine)
	}
	ms, err := runningMachines()
	if err != nil {
		// No UI to ask: list what we can see directly.
		for _, li := range limaInstances() {
			ms = append(ms, Machine{Name: li.Name, Kind: "lima", Status: li.Status})
		}
	}
	for _, m := range ms {
		label := "VM"
		if m.Kind == "local" {
			label = "this host"
		}
		line := fmt.Sprintf("%-10s %-12s %-8s", label, m.Name, strings.ToLower(m.Status))
		if m.Status == "Running" {
			if m.Version == "" {
				line += "  (sydguard daemon not running; starts on the next run)"
			} else {
				line += fmt.Sprintf("  %d agent(s)", m.Agents)
			}
			if m.Version != "" {
				line += "  build " + m.Version
				if m.Kind == "lima" {
					if guestBuilds()[m.Version] {
						line += " (current)"
					} else {
						line += " (outdated: next run updates it, or sydguard prepare)"
					}
				}
			}
		}
		fmt.Println(line)
	}
	return nil
}

// Stop stops the UI server and sydguard daemons (and, with vms, the Lima VMs).
// Refuses while agents run unless force.
func Stop(force, vms bool) error {
	ms, _ := runningMachines()
	if ms == nil {
		for _, li := range limaInstances() {
			ms = append(ms, Machine{Name: li.Name, Kind: "lima", Status: li.Status})
		}
	}
	total := 0
	for _, m := range ms {
		total += m.Agents
	}
	if total > 0 && !force {
		return fmt.Errorf("%d agent(s) running (their network and approvals would stop); stop them or use --force", total)
	}
	if err := killUIServer(); err == nil {
		fmt.Println("stopped UI")
	}
	for _, m := range ms {
		switch {
		case m.Kind == "local":
			stopDaemon("")
			fmt.Println("stopped daemon on this host")
		case m.Status == "Running" && vms:
			if err := exec.Command("limactl", "stop", m.Name).Run(); err != nil {
				return fmt.Errorf("stopping VM %s: %w", m.Name, err)
			}
			fmt.Println("stopped VM", m.Name)
		case m.Status == "Running":
			stopDaemon(m.Name)
			fmt.Println("stopped daemon in VM", m.Name)
		}
	}
	return nil
}

// Restart replaces the UI server and daemons with this build. Running agents
// keep going (daemons re-adopt them; proxied connections reconnect).
func Restart() error {
	_ = killUIServer()
	for _, li := range limaInstances() {
		if li.Status == "Running" {
			_ = exec.Command("limactl", "shell", li.Name, "sh", "-c", "~/.local/bin/sydguard daemon-stop; ~/.local/bin/sydguard daemon-ensure").Run()
		}
	}
	if system.RunsSyd() && !system.InLima() {
		exe, _ := os.Executable()
		_ = exec.Command(exe, "daemon-stop").Run()
		_ = exec.Command(exe, "daemon-ensure").Run()
	}
	if _, err := EnsureServer(); err != nil {
		return err
	}
	fmt.Println("restarted:", URL())
	return nil
}

// stopDaemon asks a daemon (this host when vm is "") to exit.
func stopDaemon(vm string) {
	if vm == "" {
		exe, _ := os.Executable()
		_ = exec.Command(exe, "daemon-stop").Run()
		return
	}
	_ = exec.Command("limactl", "shell", vm, "sh", "-c", "~/.local/bin/sydguard daemon-stop").Run()
}
