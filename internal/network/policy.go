// Package network provides an operator-authorized domain/port proxy, not syscall
// enforcement. Syd independently denies all direct workload network connections.
package network

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type (
	Target struct {
		Host      string `json:"host"`
		Port      uint16 `json:"port"`
		Transport string `json:"transport"`
	}
	Pending struct {
		ID          string    `json:"id"`
		SessionID   string    `json:"session_id"`
		SessionName string    `json:"session_name"`
		Target      Target    `json:"target"`
		FirstSeen   time.Time `json:"first_seen"`
		Attempts    int       `json:"attempts"`
	}
	Decision struct {
		ID     string `json:"id"`
		Action string `json:"action"`
		Scope  string `json:"scope"`
	}
)

type Policy struct {
	mu      sync.Mutex
	file    string
	durable map[Target]bool
	run     map[string]map[Target]bool
	denied  map[string]map[Target]bool
	pending map[string]Pending
	ended   map[string]bool
}

func Canonical(host string, port uint16) (Target, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if _, err := netip.ParseAddr(host); err == nil {
		return Target{}, fmt.Errorf("IP literals are not DNS hostname grants")
	}
	if port == 0 || len(host) > 253 || !strings.Contains(host, ".") {
		return Target{}, fmt.Errorf("requires exact DNS hostname and nonzero port")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return Target{}, fmt.Errorf("invalid hostname label")
		}
		for _, c := range label {
			allowed := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
			if !allowed {
				return Target{}, fmt.Errorf("only literal ASCII DNS names are supported")
			}
		}
	}
	return Target{Host: host, Port: port, Transport: "tcp"}, nil
}

func NewPolicy(file string) (*Policy, error) {
	p := &Policy{file: file, durable: map[Target]bool{}, run: map[string]map[Target]bool{}, denied: map[string]map[Target]bool{}, pending: map[string]Pending{}, ended: map[string]bool{}}
	if file == "" {
		return p, nil
	}
	info, err := os.Lstat(file)
	if os.IsNotExist(err) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 1024*1024 {
		return nil, fmt.Errorf("unsafe network policy file")
	}
	f, err := os.Open(file) //nolint:gosec // operator-selected policy inside protected state; regular-file/mode/size validated above
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	decoder := json.NewDecoder(io.LimitReader(f, 1024*1024))
	decoder.DisallowUnknownFields()
	var data struct {
		Version int      `json:"version"`
		Rules   []Target `json:"rules"`
	}
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF || data.Version != 1 || len(data.Rules) > 4096 {
		return nil, fmt.Errorf("invalid network policy")
	}
	for _, rule := range data.Rules {
		target, err := Canonical(rule.Host, rule.Port)
		if err != nil || target != rule {
			return nil, fmt.Errorf("invalid persisted network target")
		}
		p.durable[target] = true
	}
	return p, nil
}

// Check is called by the trusted proxy on the actual connection request. DNS
// queries do not create candidates; target ports come from HTTP/CONNECT intent.
func (p *Policy) Check(session, name string, target Target) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ended[session] || p.denied[session][target] {
		return false
	}
	if p.durable[target] || p.run[session][target] {
		return true
	}
	for id, value := range p.pending {
		if value.SessionID == session && value.Target == target {
			value.Attempts++
			p.pending[id] = value
			return false
		}
	}
	if len(p.pending) >= 128 {
		return false
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return false
	}
	id := hex.EncodeToString(entropy[:])
	p.pending[id] = Pending{ID: id, SessionID: session, SessionName: name, Target: target, FirstSeen: time.Now().UTC(), Attempts: 1}
	return false
}

func (p *Policy) Pending() []Pending {
	p.mu.Lock()
	defer p.mu.Unlock()
	values := make([]Pending, 0, len(p.pending))
	for _, value := range p.pending {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].FirstSeen.Before(values[j].FirstSeen) })
	return values
}
func (p *Policy) Rules() []Target { p.mu.Lock(); defer p.mu.Unlock(); return sorted(p.durable) }

func (p *Policy) Decide(d Decision) error {
	return p.DecideWithApply(d, nil)
}

// DecideWithApply commits only after the typed backend operation succeeds.
func (p *Policy) DecideWithApply(d Decision, apply func(Pending) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	value, ok := p.pending[d.ID]
	if !ok {
		return fmt.Errorf("pending request no longer exists")
	}
	if d.Action != "allow" && d.Action != "deny" {
		return fmt.Errorf("decision must allow or deny")
	}
	if d.Scope != "run" && d.Scope != "saved" {
		return fmt.Errorf("scope must be run or saved")
	}
	if d.Action == "deny" && d.Scope != "run" {
		return fmt.Errorf("saved deny is not supported yet")
	}
	if d.Action == "allow" && apply != nil {
		if err := apply(value); err != nil {
			return err
		}
	}
	if d.Scope == "saved" {
		next := make(map[Target]bool, len(p.durable)+1)
		for rule := range p.durable {
			next[rule] = true
		}
		next[value.Target] = true
		if len(next) > 4096 {
			return fmt.Errorf("saved rule limit reached")
		}
		if err := p.save(next); err != nil {
			return err
		}
		p.durable = next
	} else {
		rules := p.run
		if d.Action == "deny" {
			rules = p.denied
		}
		if rules[value.SessionID] == nil {
			rules[value.SessionID] = map[Target]bool{}
		}
		rules[value.SessionID][value.Target] = true
	}
	delete(p.pending, d.ID)
	return nil
}

// AllowTrusted applies an explicit launcher-authorized target only after backend acknowledgement.
func (p *Policy) AllowTrusted(session string, target Target, apply func() error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ended[session] {
		return fmt.Errorf("session ended")
	}
	if err := apply(); err != nil {
		return err
	}
	if p.run[session] == nil {
		p.run[session] = map[Target]bool{}
	}
	p.run[session][target] = true
	for id, value := range p.pending {
		if value.SessionID == session && value.Target == target {
			delete(p.pending, id)
		}
	}
	return nil
}

func (p *Policy) End(session string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ended[session] = true
	delete(p.run, session)
	delete(p.denied, session)
	for id, value := range p.pending {
		if value.SessionID == session {
			delete(p.pending, id)
		}
	}
}

func sorted(rules map[Target]bool) []Target {
	values := make([]Target, 0, len(rules))
	for value := range rules {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Host == values[j].Host {
			return values[i].Port < values[j].Port
		}
		return values[i].Host < values[j].Host
	})
	return values
}

func (p *Policy) save(rules map[Target]bool) error {
	if p.file == "" {
		return fmt.Errorf("persistent policy is unavailable")
	}
	data, err := json.MarshalIndent(struct {
		Version int      `json:"version"`
		Rules   []Target `json:"rules"`
	}{1, sorted(rules)}, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(p.file), ".policy-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), p.file)
}
