// Package files reviews trusted Syd denial events within immutable scope ceilings.
package files

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Gobd/syd-guard/internal/syd"
)

type (
	Event struct {
		Capability string `json:"cap"`
		Path       string `json:"path"`
		Action     string `json:"act"`
	}
	Pending struct {
		ID              string    `json:"id"`
		SessionID       string    `json:"session_id"`
		SessionName     string    `json:"session_name"`
		Capability      string    `json:"capability"`
		Path            string    `json:"path"`
		FirstSeen       time.Time `json:"first_seen"`
		Attempts        int       `json:"attempts"`
		RestartRequired bool      `json:"restart_required,omitempty"`
	}
	Decision struct {
		ID     string `json:"id"`
		Action string `json:"action"`
		Scope  string `json:"scope"`
	}
	Context struct {
		Socket          string   `json:"socket"`
		Scopes          []string `json:"scopes"`
		Protected       []string `json:"protected"`
		PolicyDirectory string   `json:"-"`
	}
	sessionContext struct {
		Context
		name string
	}
	Manager struct {
		mu       sync.Mutex
		sessions map[string]sessionContext
		pending  map[string]Pending
		denied   map[string]bool
	}
)

func New() *Manager {
	return &Manager{sessions: map[string]sessionContext{}, pending: map[string]Pending{}, denied: map[string]bool{}}
}

func (m *Manager) Register(id, name string, value Context) error {
	if len(value.Scopes) == 0 || !filepath.IsAbs(value.Socket) {
		return fmt.Errorf("file learning requires declared scopes and private IPC")
	}
	roots := make([]string, 0, len(value.Scopes))
	for _, root := range value.Scopes {
		path, err := filepath.EvalSymlinks(root)
		if err != nil || !filepath.IsAbs(path) {
			return fmt.Errorf("invalid filesystem ceiling")
		}
		roots = append(roots, path)
	}
	value.Scopes = roots
	protected := make([]string, 0, len(value.Protected))
	for _, path := range value.Protected {
		resolved, err := canonical(path)
		if err != nil {
			return err
		}
		protected = append(protected, resolved)
	}
	value.Protected = protected
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[id] = sessionContext{Context: value, name: name}
	return nil
}

func canonical(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n*?[]{}\\$;!") {
		return "", fmt.Errorf("path cannot be safely granted")
	}
	path = filepath.Clean(path)
	if value, err := filepath.EvalSymlinks(path); err == nil {
		return value, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}

func within(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

func protectedPath(value sessionContext, path, capability string) bool {
	if syd.ProtectedPath(path, capability, value.PolicyDirectory) {
		return true
	}
	for _, protected := range value.Protected {
		if within(path, protected) || within(protected, path) {
			return true
		}
	}
	return false
}

func authorized(value sessionContext, path, capability string) bool {
	if protectedPath(value, path, capability) {
		return false
	}
	for _, root := range value.Scopes {
		if within(path, root) {
			return true
		}
	}
	return false
}

func (m *Manager) Observe(id string, event Event) {
	if event.Action != "deny" || !syd.FileCapability(event.Capability) {
		return
	}
	path, err := canonical(event.Path)
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.sessions[id]
	if !ok || protectedPath(value, event.Path, event.Capability) || protectedPath(value, path, event.Capability) {
		return
	}
	key := id + "\x00" + event.Capability + "\x00" + path
	if m.denied[key] {
		return
	}
	for requestID, pending := range m.pending {
		if pending.SessionID == id && pending.Path == path && pending.Capability == event.Capability {
			pending.Attempts++
			m.pending[requestID] = pending
			return
		}
	}
	if len(m.pending) >= 128 {
		return
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return
	}
	requestID := hex.EncodeToString(entropy[:])
	m.pending[requestID] = Pending{ID: requestID, SessionID: id, SessionName: value.name, Capability: event.Capability, Path: path, FirstSeen: time.Now().UTC(), Attempts: 1, RestartRequired: !authorized(value, path, event.Capability)}
}

func (m *Manager) Pending() []Pending {
	m.mu.Lock()
	defer m.mu.Unlock()
	values := make([]Pending, 0, len(m.pending))
	for _, value := range m.pending {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].FirstSeen.Before(values[j].FirstSeen) })
	return values
}

func (m *Manager) Decide(ctx context.Context, decision Decision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	request, ok := m.pending[decision.ID]
	if !ok {
		return fmt.Errorf("request no longer exists")
	}
	value, ok := m.sessions[request.SessionID]
	if !ok {
		return fmt.Errorf("session has ended")
	}
	if decision.Scope != "run" {
		return fmt.Errorf("file grants currently support run scope only")
	}
	if decision.Action == "deny" {
		m.denied[request.SessionID+"\x00"+request.Capability+"\x00"+request.Path] = true
		delete(m.pending, decision.ID)
		return nil
	}
	if decision.Action != "allow" {
		return fmt.Errorf("decision must allow or deny")
	}
	path, err := canonical(request.Path)
	if err != nil || path != request.Path || !authorized(value, path, request.Capability) {
		return fmt.Errorf("path changed or is outside the protected immutable ceiling")
	}
	if err := (syd.IPC{Socket: value.Socket}).GrantPath(ctx, request.Capability, path); err != nil {
		return err
	}
	delete(m.pending, decision.ID)
	return nil
}

func (m *Manager) End(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	for request, value := range m.pending {
		if value.SessionID == id {
			delete(m.pending, request)
		}
	}
	for key := range m.denied {
		if strings.HasPrefix(key, id+"\x00") {
			delete(m.denied, key)
		}
	}
}
