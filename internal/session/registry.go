// Package session tracks friendly labels separately from opaque authority IDs.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

type State string

const (
	Running State = "running"
	Exited  State = "exited"
)

// SelectedProfile is launcher-reported intent, not proof that setup completed.
type SelectedProfile struct {
	ProjectID        string `json:"project_id"`
	ProfileID        string `json:"profile_id"`
	Name             string `json:"name"`
	Revision         string `json:"revision"`
	Provenance       string `json:"provenance"`
	ProvenanceDetail string `json:"provenance_detail,omitempty"`
	Applied          bool   `json:"applied"`
}

type Session struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Project         string           `json:"project"`
	Command         []string         `json:"command"`
	ArgumentCount   int              `json:"argument_count"`
	Gateway         string           `json:"gateway,omitempty"`
	Namespace       string           `json:"namespace,omitempty"`
	TransitDNS      string           `json:"transit_dns,omitempty"`
	SelectedProfile *SelectedProfile `json:"selected_profile,omitempty"`
	PID             int              `json:"pid"`
	StartIdentity   string           `json:"start_identity"`
	State           State            `json:"state"`
	StartedAt       time.Time        `json:"started_at"`
	EndedAt         *time.Time       `json:"ended_at,omitempty"`
}

type Registry struct {
	mu          sync.Mutex
	sessions    map[string]Session
	activeNames map[string]string
}

func NewRegistry() *Registry {
	return &Registry{sessions: map[string]Session{}, activeNames: map[string]string{}}
}

func (registry *Registry) Register(project, preferred string, command []string, pid int, identity string) (Session, error) {
	if !filepath.IsAbs(project) || len(command) == 0 || pid <= 0 || identity == "" {
		return Session{}, fmt.Errorf("session requires an absolute project, command and process start identity")
	}
	if preferred == "" {
		preferred = filepath.Base(filepath.Clean(project))
	}
	base := label(preferred)
	if base == "" {
		base = label(filepath.Base(command[0]))
	}
	if base == "" {
		base = "session"
	}
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return Session{}, err
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	name := base
	for suffix := 1; registry.activeNames[name] != ""; suffix++ {
		name = fmt.Sprintf("%s-%d", base, suffix)
	}
	session := Session{ID: hex.EncodeToString(bytes[:]), Name: name, Project: filepath.Clean(project), Command: []string{command[0]}, ArgumentCount: len(command) - 1, PID: pid, StartIdentity: identity, State: Running, StartedAt: time.Now().UTC()}
	registry.sessions[session.ID] = session
	registry.activeNames[name] = session.ID
	return clone(session), nil
}

// SetSelectedProfile records a trusted launch request, not an applied grant.
func (registry *Registry) SetSelectedProfile(id string, selection SelectedProfile) (Session, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	value, ok := registry.sessions[id]
	if !ok || value.State != Running {
		return Session{}, fmt.Errorf("unknown active session")
	}
	selection.Applied = false
	value.SelectedProfile = &selection
	registry.sessions[id] = value
	return clone(value), nil
}

// SetNetwork publishes controller-owned connection metadata for an active session.
func (registry *Registry) SetNetwork(id, gateway, namespace, transitDNS string) (Session, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	value, ok := registry.sessions[id]
	if !ok || value.State != Running {
		return Session{}, fmt.Errorf("unknown active session")
	}
	value.Gateway, value.Namespace, value.TransitDNS = gateway, namespace, transitDNS
	registry.sessions[id] = value
	return clone(value), nil
}

func (registry *Registry) Finish(id, identity string) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	session, ok := registry.sessions[id]
	if !ok || session.StartIdentity != identity {
		return fmt.Errorf("unknown or stale session identity")
	}
	if session.State == Exited {
		return nil
	}
	now := time.Now().UTC()
	session.State = Exited
	session.EndedAt = &now
	registry.sessions[id] = session
	delete(registry.activeNames, session.Name)
	registry.trimHistory()
	return nil
}

func (registry *Registry) Get(id string) (Session, bool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	value, exists := registry.sessions[id]
	return clone(value), exists
}

func (registry *Registry) List(history bool) []Session {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	result := make([]Session, 0, len(registry.sessions))
	for _, session := range registry.sessions {
		if history || session.State == Running {
			result = append(result, clone(session))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].StartedAt.Before(result[j].StartedAt) })
	return result
}

// Keep only the latest ended summaries; never discard a running authority ID.
func (registry *Registry) trimHistory() {
	const limit = 256
	ended := make([]Session, 0)
	for _, value := range registry.sessions {
		if value.State == Exited {
			ended = append(ended, value)
		}
	}
	if len(ended) <= limit {
		return
	}
	sort.Slice(ended, func(i, j int) bool { return ended[i].EndedAt.Before(*ended[j].EndedAt) })
	for _, value := range ended[:len(ended)-limit] {
		delete(registry.sessions, value.ID)
	}
}

func clone(session Session) Session {
	session.Command = append([]string(nil), session.Command...)
	if session.SelectedProfile != nil {
		selected := *session.SelectedProfile
		session.SelectedProfile = &selected
	}
	if session.EndedAt != nil {
		value := *session.EndedAt
		session.EndedAt = &value
	}
	return session
}

func label(name string) string {
	name = strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			return unicode.ToLower(r)
		}
		return '-'
	}, name)
	name = strings.Trim(name, "-")
	runes := []rune(name)
	if len(runes) > 48 {
		name = string(runes[:48])
	}
	return name
}
