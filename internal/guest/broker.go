package guest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Gobd/syd-guard/internal/api"
	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

// Brokered commands. Inside the sandbox, `sydguard cmd NAME k=v` sends the
// request through the session's TUN to its dedicated command-broker endpoint;
// the daemon tags it with the session's project and rules file and queues it.
// The UI server (on the host) picks it up, decides (it alone trusts command
// definitions), runs it there with your normal credentials, and answers.

// Job is one request from an agent, waiting for the host.
type Job struct {
	ID              string                    `json:"id"`
	Session         string                    `json:"session"`
	Project         string                    `json:"project"`
	RulesFile       string                    `json:"rulesFile"`
	Cmd             string                    `json:"cmd"` // the agent's command line, for display
	Op              string                    `json:"op"`  // list, run, propose
	Request         CmdRequest                `json:"request"`
	ProjectCommands map[string]policy.Command `json:"projectCommands"` // from the trusted rules file
	Created         time.Time                 `json:"created"`
	result          chan CmdResult
}

type CmdRequest struct {
	Name   string            `json:"name,omitempty"`
	Args   map[string]string `json:"args,omitempty"`
	Argv   []string          `json:"argv,omitempty"`   // propose: the exact command wanted
	Reason string            `json:"reason,omitempty"` // propose: why
	Stdin  string            `json:"stdin,omitempty"`
}

type CmdResult struct {
	Exit     int    `json:"exit"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Error    string `json:"error,omitempty"`
	Commands []struct {
		Name        string   `json:"name"`
		Args        []string `json:"args,omitempty"`
		Stdin       bool     `json:"stdin,omitempty"`
		Mode        string   `json:"mode"`
		Scope       string   `json:"scope"`
		Description string   `json:"description,omitempty"`
	} `json:"commands,omitempty"`
}

const jobTimeout = 15 * time.Minute

// serveBroker handles requests to the session's SG_BROKER endpoint.
func (d *Daemon) serveBroker(s *Session, w http.ResponseWriter, r *http.Request) {
	op := strings.Trim(r.URL.Path, "/")
	if op == "overlay" {
		var req CmdRequest
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		result, err := d.requestOverlay(s, req.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
		return
	}
	if op != "list" && op != "run" && op != "propose" {
		http.Error(w, "unknown broker operation", http.StatusNotFound)
		return
	}
	var req CmdRequest
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	j := &Job{
		ID: system.NewID(), Session: s.ID, Project: s.Project, RulesFile: s.RulesFile, Op: op, Request: req,
		ProjectCommands: d.store.Get(s.RulesFile).Commands, Created: time.Now(), result: make(chan CmdResult, 1),
	}
	if len(s.Cmd) > 0 {
		j.Cmd = strings.Join(s.Cmd, " ")
	}
	d.mu.Lock()
	if d.jobs == nil {
		d.jobs = map[string]*Job{}
	}
	d.jobs[j.ID] = j
	d.mu.Unlock()
	d.events.Notify()
	defer func() {
		d.mu.Lock()
		delete(d.jobs, j.ID)
		d.mu.Unlock()
		d.events.Notify()
	}()
	var res CmdResult
	select {
	case res = <-j.result:
	case <-r.Context().Done():
		return
	case <-time.After(jobTimeout):
		res = CmdResult{Exit: 1, Error: "no answer from the approvals UI (is it running? `sydguard ui` on the host)"}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// jobRoutes are used by the UI server.
func (d *Daemon) jobRoutes(mux *http.ServeMux) {
	api.Handle(mux, "POST /api/overlay", func(r *http.Request) (any, error) {
		var req struct{ Session, Path string }
		if err := api.Decode(r, &req); err != nil {
			return nil, err
		}
		d.mu.Lock()
		s := d.sessions[req.Session]
		d.mu.Unlock()
		if s == nil {
			return nil, errors.New("no such session")
		}
		return d.requestOverlay(s, req.Path)
	})
	api.Handle(mux, "GET /api/jobs", func(*http.Request) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		out := []*Job{}
		for _, j := range d.jobs {
			out = append(out, j)
		}
		sort.Slice(out, func(a, b int) bool { return out[a].Created.Before(out[b].Created) })
		return out, nil
	})
	api.Handle(mux, "POST /api/jobs/result", func(r *http.Request) (any, error) {
		var req struct {
			ID     string
			Result CmdResult
		}
		if err := api.Decode(r, &req); err != nil {
			return nil, err
		}
		d.mu.Lock()
		j, ok := d.jobs[req.ID]
		d.mu.Unlock()
		if !ok {
			return nil, errors.New("no such job (the agent gave up?)")
		}
		select {
		case j.result <- req.Result:
		default:
		}
		return map[string]any{}, nil
	})
	// Saving a proposed command for one project goes into its rules file.
	api.Handle(mux, "POST /api/commands/save", func(r *http.Request) (any, error) {
		var req struct {
			File    string
			Name    string
			Command policy.Command
		}
		if err := api.Decode(r, &req); err != nil {
			return nil, err
		}
		if err := system.SafePath(req.File); err != nil || !policy.ValidCommandName(req.Name) {
			return nil, errors.New("bad file or name")
		}
		if err := req.Command.Validate(); err != nil {
			return nil, err
		}
		_, _, err := d.store.Edit(req.File, func(rules *policy.Rules) error {
			if rules.Commands == nil {
				rules.Commands = map[string]policy.Command{}
			}
			rules.Commands[req.Name] = req.Command
			return nil
		})
		return map[string]any{"saved": req.File}, err
	})
}

// RunClient is `sydguard cmd` inside the sandbox.
func RunClient(args []string, stdin io.Reader) (int, error) {
	endpoint := os.Getenv("SG_BROKER")
	if endpoint == "" {
		return 2, errors.New("sydguard cmd only works inside a sydguard sandbox")
	}
	pu, err := url.Parse(endpoint)
	if err != nil {
		return 2, err
	}
	if pu.Scheme != "http" || pu.Hostname() != networkGateway || pu.Port() == "" || pu.User != nil || pu.Path != "" || pu.RawQuery != "" || pu.Fragment != "" {
		return 2, errors.New("invalid session broker endpoint")
	}
	client := &http.Client{Transport: &http.Transport{}, Timeout: jobTimeout + time.Minute}
	post := func(op string, req CmdRequest) (CmdResult, error) {
		var res CmdResult
		body, _ := json.Marshal(req)
		method := http.MethodPost
		if op == "list" {
			method, body = http.MethodGet, nil
		}
		hreq, _ := http.NewRequestWithContext(context.Background(), method, pu.String()+"/"+op, bytes.NewReader(body)) //nolint:gosec // validated session gateway; this client runs inside the sandbox
		resp, err := client.Do(hreq)                                                                                   //nolint:gosec // validated session gateway, not an operator-side fetch
		if err != nil {
			return res, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return res, fmt.Errorf("%s", strings.TrimSpace(string(b)))
		}
		return res, json.NewDecoder(resp.Body).Decode(&res)
	}
	readStdin := func() string {
		if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			return "" // a terminal, not piped input
		}
		b, _ := io.ReadAll(io.LimitReader(stdin, 1<<20))
		return string(b)
	}
	usage := errors.New(`usage:
  sydguard cmd --list                         commands you may run (on the host)
  sydguard cmd NAME key=value... [< input]    run one
  sydguard cmd --propose [--why TEXT] -- PROGRAM ARGS...   ask for a new one`)
	if len(args) == 0 {
		return 2, usage
	}
	var res CmdResult
	switch args[0] {
	case "--overlay":
		if len(args) != 2 {
			return 2, errors.New("usage: sydguard overlay add PATH")
		}
		path, pathErr := filepath.Abs(args[1])
		if pathErr != nil {
			return 2, pathErr
		}
		res, err = post("overlay", CmdRequest{Name: path})
	case "--list", "-l", "list":
		if res, err = post("list", CmdRequest{}); err != nil {
			return 1, err
		}
		if len(res.Commands) == 0 {
			fmt.Println("no commands configured; propose one with: sydguard cmd --propose -- PROGRAM ARGS...")
		}
		for _, c := range res.Commands {
			line := c.Name
			for _, a := range c.Args {
				line += " " + a + "=…"
			}
			if c.Stdin {
				line += " < input"
			}
			fmt.Printf("%-50s %s, %s%s\n", line, c.Mode, c.Scope, map[bool]string{true: " — " + c.Description, false: ""}[c.Description != ""])
		}
		return 0, nil
	case "--propose":
		rest, why := args[1:], ""
		if len(rest) >= 2 && rest[0] == "--why" {
			why, rest = rest[1], rest[2:]
		}
		if len(rest) > 0 && rest[0] == "--" {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return 2, usage
		}
		res, err = post("propose", CmdRequest{Argv: rest, Reason: why, Stdin: readStdin()})
	default:
		req := CmdRequest{Name: args[0], Args: map[string]string{}}
		for _, kv := range args[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return 2, fmt.Errorf("arguments are key=value, got %q", kv)
			}
			req.Args[k] = v
		}
		req.Stdin = readStdin()
		res, err = post("run", req)
	}
	if err != nil {
		return 1, err
	}
	_, _ = io.WriteString(os.Stdout, res.Stdout)
	_, _ = io.WriteString(os.Stderr, res.Stderr)
	if res.Error != "" {
		fmt.Fprintln(os.Stderr, "sydguard:", res.Error)
		if res.Exit == 0 {
			res.Exit = 1
		}
	}
	return res.Exit, nil
}
