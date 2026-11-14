package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Gobd/syd-guard/internal/api"
	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/guest"
	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

// The host half of brokered commands. This process alone decides what runs:
// global commands come from this machine's config; project commands come
// from the project's rules file but must be approved here once per
// definition. This validates argv, not everything the selected program might
// do with project data. Commands run in the project directory with the host's
// credentials; repository configuration and executable project files still
// belong to that command's trust boundary.

const (
	runTimeout = 10 * time.Minute
	outputCap  = 1 << 20
)

type cmdCard struct {
	ID        string    `json:"id"`
	VM        string    `json:"vm"`
	Project   string    `json:"project"`
	RulesFile string    `json:"rulesFile"`
	Agent     string    `json:"agent"`          // the agent's command line
	Kind      string    `json:"kind"`           // "run" or "propose"
	Name      string    `json:"name,omitempty"` // run: which command
	Scope     string    `json:"scope,omitempty"`
	Argv      []string  `json:"argv"`
	Stdin     string    `json:"stdin,omitempty"` // preview
	Reason    string    `json:"reason,omitempty"`
	Note      string    `json:"note,omitempty"`
	Created   time.Time `json:"created"`
	decide    chan cmdDecision
}

type cmdDecision struct {
	Action  string            `json:"action"` // run, deny, save
	Scope   string            `json:"scope"`  // save: "global" or "project"
	Name    string            `json:"name"`   // save
	Run     []string          `json:"run"`    // save: template
	Args    map[string]string `json:"args"`   // save: placeholder regexes
	Mode    string            `json:"mode"`   // save
	Stdin   bool              `json:"stdin"`  // save
	Comment string            `json:"description"`
}

type broker struct {
	mu      sync.Mutex
	handled map[string]bool
	cards   map[string]*cmdCard
}

func newBroker() *broker { return &broker{handled: map[string]bool{}, cards: map[string]*cmdCard{}} }

func (u *uiServer) pollJobs(b *backend) {
	var jobs []guest.Job
	if api.Call(b.client, "GET", "/api/jobs", nil, &jobs) != nil {
		return
	}
	for _, j := range jobs {
		u.broker.mu.Lock()
		seen := u.broker.handled[b.name+"/"+j.ID]
		u.broker.handled[b.name+"/"+j.ID] = true
		u.broker.mu.Unlock()
		if !seen {
			go func() {
				res := u.handleJob(b, j)
				_ = api.Call(b.client, "POST", "/api/jobs/result", map[string]any{"ID": j.ID, "Result": res}, nil)
			}()
		}
	}
}

type listing = struct {
	Name        string   `json:"name"`
	Args        []string `json:"args,omitempty"`
	Stdin       bool     `json:"stdin,omitempty"`
	Mode        string   `json:"mode"`
	Scope       string   `json:"scope"`
	Description string   `json:"description,omitempty"`
}

func mode(c policy.Command) string {
	if c.Mode == "allow" {
		return "allow"
	}
	return "ask"
}

func (u *uiServer) handleJob(b *backend, j guest.Job) guest.CmdResult {
	cfg, err := config.Load()
	if err != nil {
		return guest.CmdResult{Exit: 1, Error: err.Error()}
	}
	switch j.Op {
	case "list":
		var res guest.CmdResult
		add := func(name string, c policy.Command, scope string) {
			res.Commands = append(res.Commands, listing{Name: name, Args: c.ArgNames(), Stdin: c.Stdin, Mode: mode(c), Scope: scope, Description: c.Description})
		}
		for name, c := range cfg.Commands {
			if _, shadowed := j.ProjectCommands[name]; !shadowed {
				add(name, c, "all projects")
			}
		}
		for name, c := range j.ProjectCommands {
			add(name, c, "this project")
		}
		sort.Slice(res.Commands, func(a, b int) bool { return res.Commands[a].Name < res.Commands[b].Name })
		return res
	case "run":
		name := j.Request.Name
		def, scope := cfg.Commands[name], "global"
		if c, ok := j.ProjectCommands[name]; ok {
			def, scope = c, "project"
		} else if _, ok := cfg.Commands[name]; !ok {
			return guest.CmdResult{Exit: 2, Error: fmt.Sprintf("no command %q (see `sydguard cmd --list`, or propose one)", name)}
		}
		argv, err := def.Expand(j.Request.Args)
		if err != nil {
			return guest.CmdResult{Exit: 2, Error: err.Error()}
		}
		stdin := ""
		if def.Stdin {
			stdin = j.Request.Stdin
		}
		trusted := scope == "global" || projectApproved(j.RulesFile, name, def)
		if mode(def) == "allow" && trusted {
			return u.execute(b, j, argv, stdin)
		}
		note := ""
		if !trusted {
			note = "project command from " + filepath.Base(j.RulesFile) + ", not yet approved on this machine; running it approves its definition"
		}
		d := u.ask(b, j, &cmdCard{Kind: "run", Name: name, Scope: scope, Argv: argv, Stdin: preview(stdin), Note: note})
		if d.Action != "run" {
			return guest.CmdResult{Exit: 1, Error: "denied"}
		}
		if !trusted {
			_ = approveProject(j.RulesFile, name, def)
		}
		return u.execute(b, j, argv, stdin)
	case "propose":
		if len(j.Request.Argv) == 0 || j.Request.Argv[0] == "" {
			return guest.CmdResult{Exit: 2, Error: "empty command"}
		}
		d := u.ask(b, j, &cmdCard{Kind: "propose", Argv: j.Request.Argv, Stdin: preview(j.Request.Stdin), Reason: j.Request.Reason})
		switch d.Action {
		case "run":
			return u.execute(b, j, j.Request.Argv, j.Request.Stdin)
		case "save":
			c := policy.Command{Run: d.Run, Args: d.Args, Mode: d.Mode, Stdin: d.Stdin, Description: d.Comment}
			if err := u.saveCommand(b, j, d.Scope, d.Name, c); err != nil {
				return guest.CmdResult{Exit: 1, Error: "saving failed: " + err.Error()}
			}
			return guest.CmdResult{Exit: 0, Stderr: fmt.Sprintf("saved as `%s`; run it with: sydguard cmd %s%s\n", d.Name, d.Name, argHint(c))}
		}
		return guest.CmdResult{Exit: 1, Error: "denied"}
	}
	return guest.CmdResult{Exit: 2, Error: "unknown operation"}
}

func argHint(c policy.Command) string {
	var s string
	for _, a := range c.ArgNames() {
		s += " " + a + "=…"
	}
	return s
}

func preview(s string) string {
	if len(s) > 2000 {
		return s[:2000] + "\n…"
	}
	return s
}

// ask shows a card and waits for your decision.
func (u *uiServer) ask(b *backend, j guest.Job, c *cmdCard) cmdDecision {
	c.ID, c.VM, c.Project, c.RulesFile, c.Agent, c.Created = system.NewID(), b.name, j.Project, j.RulesFile, j.Cmd, time.Now()
	c.decide = make(chan cmdDecision, 1)
	u.broker.mu.Lock()
	u.broker.cards[c.ID] = c
	u.broker.mu.Unlock()
	u.events.Notify()
	defer func() {
		u.broker.mu.Lock()
		delete(u.broker.cards, c.ID)
		u.broker.mu.Unlock()
		u.events.Notify()
	}()
	select {
	case d := <-c.decide:
		return d
	case <-time.After(14 * time.Minute):
		return cmdDecision{Action: "deny"}
	}
}

func (u *uiServer) decide(id string, d cmdDecision) error {
	u.broker.mu.Lock()
	c, ok := u.broker.cards[id]
	u.broker.mu.Unlock()
	if !ok {
		return errors.New("that request is gone (the agent gave up?)")
	}
	if d.Action == "save" {
		if !policy.ValidCommandName(d.Name) {
			return errors.New("name: lowercase letters, digits, - and _")
		}
		if err := (policy.Command{Run: d.Run, Args: d.Args, Mode: d.Mode}).Validate(); err != nil {
			return err
		}
		if d.Scope != "global" && d.Scope != "project" {
			return errors.New("scope must be global or project")
		}
	}
	select {
	case c.decide <- d:
	default:
	}
	return nil
}

func (u *uiServer) commandCards() []cmdCard {
	u.broker.mu.Lock()
	defer u.broker.mu.Unlock()
	out := make([]cmdCard, 0, len(u.broker.cards))
	for _, c := range u.broker.cards {
		out = append(out, *c)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Created.Before(out[b].Created) })
	return out
}

func (u *uiServer) saveCommand(b *backend, j guest.Job, scope, name string, c policy.Command) error {
	if scope == "global" {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if cfg.Commands == nil {
			cfg.Commands = map[string]policy.Command{}
		}
		cfg.Commands[name] = c
		return config.Save(cfg)
	}
	if err := api.Call(b.client, "POST", "/api/commands/save", map[string]any{"File": j.RulesFile, "Name": name, "Command": c}, nil); err != nil {
		return err
	}
	return approveProject(j.RulesFile, name, c)
}

// execute runs argv on this machine in the project directory.
func (u *uiServer) execute(b *backend, j guest.Job, argv []string, stdin string) guest.CmdResult {
	dir, err := hostPath(b, j.Project)
	if err != nil {
		return guest.CmdResult{Exit: 1, Error: err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = brokerEnvironment()
	cmd.Stdin = strings.NewReader(stdin)
	var out, errOut capped
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	res := guest.CmdResult{Stdout: out.String(), Stderr: errOut.String()}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		res.Exit = exit.ExitCode()
	case err != nil:
		res.Exit, res.Error = 1, err.Error()
	}
	return res
}

// brokerEnvironment applies to Git invoked directly and by tools such as gh.
// Keep the operator's explicit SSH setup, but never take an SSH executable from
// repository-local core.sshCommand. Restrict transports to normal HTTPS/SSH:
// ext/custom helpers and local pushes can execute programs outside this broker.
// This is defense in depth, not a sandbox for arbitrary configured commands.
func brokerEnvironment() []string {
	ssh := os.Getenv("GIT_SSH_COMMAND")
	if ssh == "" {
		ssh = "ssh"
		if path := os.Getenv("GIT_SSH"); path != "" {
			ssh = "'" + strings.ReplaceAll(path, "'", "'\\''") + "'"
		}
	}
	return append(os.Environ(), "GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_VALUE_0=/dev/null",
		"GIT_CONFIG_KEY_1=core.fsmonitor", "GIT_CONFIG_VALUE_1=false",
		"GIT_SSH_COMMAND="+ssh, "GIT_ALLOW_PROTOCOL=https:ssh",
		"GIT_TERMINAL_PROMPT=0")
}

type capped struct{ bytes.Buffer }

func (c *capped) Write(p []byte) (int, error) {
	if room := outputCap - c.Len(); room > 0 {
		if len(p) > room {
			c.Buffer.Write(p[:room])
			_, _ = c.WriteString("\n[output truncated]\n")
		} else {
			c.Buffer.Write(p)
		}
	}
	return len(p), nil
}

// hostPath maps a project path inside a VM to this machine (same path when
// local or mounted at the same place).
func hostPath(b *backend, guestPath string) (string, error) {
	if !b.lima {
		return guestPath, nil
	}
	out, err := exec.Command("limactl", "list", "--format", "{{json .Config.Mounts}}", b.name).Output()
	if err != nil {
		return "", err
	}
	var mounts []struct{ Location, MountPoint string }
	if err := json.Unmarshal(out, &mounts); err != nil {
		return "", err
	}
	for _, m := range mounts {
		loc := system.ExpandHome(m.Location)
		mp := m.MountPoint
		if mp == "" {
			mp = loc
		}
		if system.Under(guestPath, mp) {
			p := loc + strings.TrimPrefix(guestPath, mp)
			if fi, err := os.Stat(p); err == nil && fi.IsDir() {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("%s isn't a folder shared from this machine; commands run here, in your project", guestPath)
}

// Host-side approvals of project command definitions.
func approvalsPath() string { return filepath.Join(system.ConfigDir(), "approved-commands.json") }

func approvalKey(rulesFile, name string, c policy.Command) string {
	return system.HashBytes([]byte(rulesFile + "\x00" + name + "\x00" + c.Hash()))
}

func loadApprovals() map[string]bool {
	m := map[string]bool{}
	if data, err := os.ReadFile(approvalsPath()); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

func projectApproved(rulesFile, name string, c policy.Command) bool {
	return loadApprovals()[approvalKey(rulesFile, name, c)]
}

func approveProject(rulesFile, name string, c policy.Command) error {
	m := loadApprovals()
	m[approvalKey(rulesFile, name, c)] = true
	data, _ := json.Marshal(m)
	if err := os.MkdirAll(filepath.Dir(approvalsPath()), 0o700); err != nil {
		return err
	}
	return os.WriteFile(approvalsPath(), data, 0o600)
}

func (u *uiServer) brokerRoutes(handle func(string, api.Func)) {
	handle("POST /api/command", func(r *http.Request) (any, error) {
		var req struct {
			ID string `json:"id"`
			cmdDecision
		}
		if err := api.Decode(r, &req); err != nil {
			return nil, err
		}
		return map[string]any{}, u.decide(req.ID, req.cmdDecision)
	})
}
