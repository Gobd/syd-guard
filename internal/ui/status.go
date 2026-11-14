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
	UIStatus()
	ListMachines()
	return nil
}

// UIStatus prints whether the UI server runs and which build.
func UIStatus() {
	mine := system.Version()
	switch v := ping(); v {
	case "":
		fmt.Println("UI         not running (start: sydguard ui)")
	case mine:
		fmt.Printf("UI         running  %s  pid %s  build %s (current)\n", URL(), pidOf("ui"), v)
	default:
		fmt.Printf("UI         running  %s  pid %s  build %s (OUTDATED: this binary is %s; sydguard ui restart)\n", URL(), pidOf("ui"), v, mine)
	}
}

func machinesNow() []Machine {
	ms, err := runningMachines()
	if err != nil { // no UI to ask: list what we can see directly
		ms = nil
		for _, li := range limaInstances() {
			ms = append(ms, Machine{Name: li.Name, Kind: "lima", Status: li.Status})
		}
	}
	return ms
}

// ListMachines prints this host (if it runs agents) and every Lima VM.
func ListMachines() {
	ms := machinesNow()
	if len(ms) == 0 {
		fmt.Println("no VMs (sydguard vm start creates one)")
	}
	for _, m := range ms {
		label := "VM"
		if m.Kind == "local" {
			label = "this host"
		}
		line := fmt.Sprintf("%-10s %-12s %-8s", label, m.Name, strings.ToLower(m.Status))
		switch {
		case m.Status != "Running":
		case m.Version == "":
			line += "  (not connected: reconnecting, or the daemon starts on the next run)"
		default:
			line += fmt.Sprintf("  %d agent(s)  build %s", m.Agents, m.Version)
			if m.Kind == "lima" {
				if guestBuilds()[m.Version] {
					line += " (current)"
				} else {
					line += " (outdated: next run updates it, or sydguard vm start)"
				}
			}
		}
		fmt.Println(line)
	}
}

// StartUI starts the UI server without opening a browser.
func StartUI() error {
	if _, err := EnsureServer(); err != nil {
		return err
	}
	UIStatus()
	return nil
}

// StopUI stops only the UI server; agents and their daemons keep running.
func StopUI() error {
	if ping() == "" {
		fmt.Println("UI not running")
		return nil
	}
	if err := killUIServer(); err != nil {
		return err
	}
	fmt.Println("stopped UI (agents keep running; approvals wait until it's back)")
	return nil
}

// StopVMs shuts down Lima VMs: the named ones, or all running ones when names
// is empty. Refuses VMs with agents unless force.
func StopVMs(names []string, force bool) error {
	ms := machinesNow()
	agents := map[string]int{}
	for _, m := range ms {
		agents[m.Name] = m.Agents
	}
	if len(names) == 0 {
		for _, m := range ms {
			if m.Kind == "lima" && m.Status == "Running" {
				names = append(names, m.Name)
			}
		}
	}
	if len(names) == 0 {
		fmt.Println("no running VMs")
	}
	for _, n := range names {
		count := agents[n]
		if force {
			count = 0
		}
		if err := vmAction(n, "stop", count); err != nil {
			return err
		}
		fmt.Println("stopped VM", n)
	}
	return nil
}

// Restart replaces the UI server and the daemons with this build. Running agents
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
