package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Command is a brokered command: run on the host (outside the sandbox, with
// your normal credentials) when the agent asks via `sydguard cmd NAME k=v`.
// The argv is fixed; the agent only fills in {placeholders}, each matching its
// regex. No shell is involved. git hooks are always disabled.
type Command struct {
	Run         []string          `json:"run"`                   // argv; "{name}" placeholders
	Args        map[string]string `json:"args,omitempty"`        // placeholder -> regex (whole value)
	Mode        string            `json:"mode,omitempty"`        // "allow" (run) or "ask" (card each time; default)
	Stdin       bool              `json:"stdin,omitempty"`       // pass the agent's stdin (e.g. a PR body)
	Description string            `json:"description,omitempty"` // shown to the agent in `sydguard cmd --list`
}

var (
	placeholder = regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`)
	commandName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,40}$`)
)

func ValidCommandName(n string) bool { return commandName.MatchString(n) }

// Validate checks the definition itself.
func (c Command) Validate() error {
	if len(c.Run) == 0 || c.Run[0] == "" || strings.Contains(c.Run[0], "{") {
		return fmt.Errorf("run must start with a fixed program")
	}
	if c.Mode != "" && c.Mode != "allow" && c.Mode != "ask" {
		return fmt.Errorf("mode must be allow or ask")
	}
	used := map[string]bool{}
	for _, a := range c.Run {
		if strings.ContainsRune(a, 0) {
			return fmt.Errorf("bad argument")
		}
		for _, m := range placeholder.FindAllStringSubmatch(a, -1) {
			used[m[1]] = true
		}
	}
	for name := range used {
		re, ok := c.Args[name]
		if !ok {
			return fmt.Errorf("{%s} has no regex in args", name)
		}
		if _, err := regexp.Compile("^(?:" + re + ")$"); err != nil {
			return fmt.Errorf("args.%s: %w", name, err)
		}
	}
	for name := range c.Args {
		if !used[name] {
			return fmt.Errorf("args.%s isn't used in run", name)
		}
	}
	return nil
}

// Expand fills in the placeholders after checking every value.
func (c Command) Expand(values map[string]string) ([]string, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	for k := range values {
		if _, ok := c.Args[k]; !ok {
			return nil, fmt.Errorf("unknown argument %q (expects %s)", k, strings.Join(c.ArgNames(), ", "))
		}
	}
	for name, re := range c.Args {
		v, ok := values[name]
		if !ok {
			return nil, fmt.Errorf("missing argument %s=…", name)
		}
		if strings.HasPrefix(v, "-") || strings.ContainsAny(v, "\x00\n\r") {
			return nil, fmt.Errorf("%s: values can't start with '-' or contain newlines", name)
		}
		if !regexp.MustCompile("^(?:" + re + ")$").MatchString(v) {
			return nil, fmt.Errorf("%s=%q doesn't match %s", name, v, re)
		}
	}
	out := make([]string, len(c.Run))
	for i, a := range c.Run {
		out[i] = placeholder.ReplaceAllStringFunc(a, func(m string) string { return values[m[1:len(m)-1]] })
	}
	return out, nil
}

func (c Command) ArgNames() []string {
	var out []string
	for k := range c.Args {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Hash identifies a definition (host-side approval of project commands).
func (c Command) Hash() string {
	data, _ := json.Marshal(c) // map keys marshal sorted
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ValidateCommands checks a whole command map.
func ValidateCommands(m map[string]Command) error {
	for name, c := range m {
		if !ValidCommandName(name) {
			return fmt.Errorf("bad command name %q", name)
		}
		if err := c.Validate(); err != nil {
			return fmt.Errorf("command %s: %w", name, err)
		}
	}
	return nil
}
