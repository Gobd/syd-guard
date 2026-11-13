// Package controller is the trusted Linux-side session/approval authority.
package controller

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/Gobd/syd-guard/internal/files"
	"github.com/Gobd/syd-guard/internal/network"

	"github.com/Gobd/syd-guard/internal/session"
)

// Server's operator token is never supplied to a workload. Unix socket privacy,
// Syd control-path denial and later browser auth are separate necessary layers.
type Server struct {
	token        string
	registry     *session.Registry
	identity     func(int) (string, error)
	network      *network.Policy
	allocator    *network.SyntheticAllocator
	files        *files.Manager
	gatesMu      sync.Mutex
	gates        map[string]*network.Gateway
	transparent  map[string]*transparentSession
	state        string
	closed       bool
	profiles     ProfileProvider
	profilesMu   sync.Mutex
	saveMu       sync.Mutex
	liveMu       sync.Mutex
	live         map[string]*liveBinding
	candidateIDs map[string]string
}

func New(token string) (*Server, error) {
	if len(token) < 32 {
		return nil, fmt.Errorf("operator token is too short")
	}
	policy, err := network.NewPolicy("")
	if err != nil {
		return nil, err
	}
	return &Server{token: token, registry: session.NewRegistry(), identity: session.ProcessIdentity, network: policy, allocator: network.NewSyntheticAllocator(), files: files.New(), gates: map[string]*network.Gateway{}, transparent: map[string]*transparentSession{}}, nil
}

// SetProfileProvider installs a trusted provider before the server starts serving.
func (server *Server) SetProfileProvider(provider ProfileProvider) { server.profiles = provider }

func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusOK, map[string]any{"service": "sydguard", "protocol": 3, "mutable_ready": false, "learning": true})
	})
	mux.HandleFunc("GET /api/sessions", func(w http.ResponseWriter, r *http.Request) {
		server.reap()
		values := server.registry.List(r.URL.Query().Get("history") == "true")
		for i := range values {
			values[i].ManagedLive = server.liveStatus(values[i].ID)
		}
		reply(w, http.StatusOK, values)
	})
	mux.HandleFunc("GET /api/profiles", server.profileList)
	mux.HandleFunc("GET /api/profiles/{id}", server.profileGet)
	mux.HandleFunc("PUT /api/profiles/{id}", server.profileSave)
	mux.HandleFunc("POST /api/profiles/{id}/reload", server.profileReload)
	mux.HandleFunc("POST /api/sessions", server.register)
	mux.HandleFunc("POST /api/sessions/{id}/finish", server.finish)
	mux.HandleFunc("POST /api/sessions/{id}/complete", server.complete)
	mux.HandleFunc("POST /api/sessions/{id}/files", server.fileReady)
	mux.HandleFunc("POST /api/sessions/{id}/events", server.fileEvent)
	mux.HandleFunc("POST /api/sessions/{id}/network-ready", server.networkReady)
	mux.HandleFunc("POST /api/sessions/{id}/network-event", server.networkEvent)
	mux.HandleFunc("POST /api/sessions/{id}/learning-dials", server.learningDials)
	mux.HandleFunc("GET /api/files/pending", func(w http.ResponseWriter, _ *http.Request) { reply(w, http.StatusOK, server.files.Pending()) })
	mux.HandleFunc("POST /api/files/decisions", func(w http.ResponseWriter, r *http.Request) {
		var decision files.Decision
		if err := decode(w, r, &decision); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if err := server.files.Decide(r.Context(), decision); err != nil {
			reply(w, 409, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, map[string]string{"status": "applied; retry the operation"})
	})
	mux.HandleFunc("GET /api/network/pending", func(w http.ResponseWriter, _ *http.Request) { reply(w, http.StatusOK, server.network.Pending()) })
	mux.HandleFunc("GET /api/network/rules", func(w http.ResponseWriter, _ *http.Request) { reply(w, http.StatusOK, server.network.Rules()) })
	mux.HandleFunc("POST /api/network/decisions", func(w http.ResponseWriter, r *http.Request) {
		var decision network.Decision
		if err := decode(w, r, &decision); err != nil {
			reply(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := server.decideNetwork(r.Context(), decision); err != nil {
			reply(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		reply(w, http.StatusOK, map[string]string{"status": "applied; retry the request"})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare([]byte(provided), []byte(server.token)) != 1 {
			reply(w, http.StatusUnauthorized, map[string]string{"error": "operator authorization required"})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func (server *Server) register(w http.ResponseWriter, r *http.Request) {
	var input Registration
	if err := decode(w, r, &input); err != nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if input.SelectedProfile != nil {
		selection := input.SelectedProfile
		revision, err := hex.DecodeString(selection.Revision)
		invalidProvenance := selection.Provenance == "manual/unknown" && selection.ProvenanceDetail != "" || selection.Provenance == "learned-reviewed" && selection.ProvenanceDetail == "" || selection.Provenance != "manual/unknown" && selection.Provenance != "learned-reviewed" || len(selection.ProvenanceDetail) > 1024 || !utf8.ValidString(selection.ProvenanceDetail) || strings.IndexFunc(selection.ProvenanceDetail, unicode.IsControl) >= 0
		if input.NetworkProxy || input.Transparent || input.Learning || selection.Applied || invalidProvenance || validateManagedProfileRef(ManagedProfileRef{ProjectID: selection.ProjectID, Name: selection.Name}) != nil || len(revision) != 32 || err != nil || hex.EncodeToString(revision) != selection.Revision || selection.ProfileID != ManagedProfileID(selection.ProjectID, selection.Name) {
			reply(w, 400, map[string]string{"error": "invalid managed selection"})
			return
		}
	}
	if input.NetworkProxy && input.Transparent || len(input.Services) > 0 && !input.Transparent || input.Learning && (!input.Transparent || len(input.Services) != 0) {
		reply(w, 400, map[string]string{"error": "transparent and proxy modes are exclusive; services require transparent mode"})
		return
	}
	port, err := servicePort(input.Services)
	if err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	server.gatesMu.Lock()
	defer server.gatesMu.Unlock()
	if server.closed {
		reply(w, 503, map[string]string{"error": "controller closed"})
		return
	}
	identity, err := server.identity(input.PID)
	if err != nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": "cannot establish process start identity"})
		return
	}
	registered, err := server.registry.Register(input.Project, input.Name, input.Command, input.PID, identity)
	if err != nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if input.SelectedProfile != nil {
		registered, err = server.registry.SetSelectedProfile(registered.ID, *input.SelectedProfile)
		if err != nil {
			_ = server.registry.Finish(registered.ID, registered.StartIdentity)
			reply(w, 500, map[string]string{"error": "managed session binding failed"})
			return
		}
	}
	if input.NetworkProxy {
		gate, err := network.Start(server.network, registered.ID, registered.Name)
		if err != nil {
			_ = server.registry.Finish(registered.ID, registered.StartIdentity)
			reply(w, http.StatusInternalServerError, map[string]string{"error": "proxy startup failed"})
			return
		}
		server.gates[registered.ID] = gate
		registered, _ = server.registry.SetNetwork(registered.ID, gate.Address, "", "")
	}
	if input.Transparent {
		host := ""
		if port != 0 {
			host = input.Services[0].Name + ".sydguard.internal"
		}
		t, topology, err := server.startTransparent(r.Context(), registered, host, port, input.Learning)
		if err != nil {
			_ = server.registry.Finish(registered.ID, registered.StartIdentity)
			server.network.End(registered.ID)
			reply(w, 500, map[string]string{"error": fmt.Sprintf("transparent setup failed: %.512s", err.Error())})
			return
		}
		server.transparent[registered.ID] = t
		registered, _ = server.registry.SetNetwork(registered.ID, "", topology.Namespace, topology.Host.String())
	}
	reply(w, http.StatusCreated, registered)
}

func (server *Server) finish(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Identity string `json:"start_identity"`
	}
	if err := decode(w, r, &input); err != nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	server.gatesMu.Lock()
	defer server.gatesMu.Unlock()
	registered, exists := server.registry.Get(r.PathValue("id"))
	if !exists {
		reply(w, http.StatusNotFound, map[string]string{"error": "unknown session"})
		return
	}
	if current, err := server.identity(registered.PID); err == nil && current == registered.StartIdentity {
		reply(w, http.StatusConflict, map[string]string{"error": "process is still active; finish does not terminate it"})
		return
	}
	if err := server.endSession(r.PathValue("id"), input.Identity); err != nil {
		reply(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	reply(w, http.StatusOK, map[string]string{"state": "exited"})
}

// complete is an explicit trusted supervisor report, not inferred process death.
// It means the foreground command returned; it does not certify no descendants.
func (server *Server) complete(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Identity string `json:"start_identity"`
	}
	if err := decode(w, r, &input); err != nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	server.gatesMu.Lock()
	defer server.gatesMu.Unlock()
	if err := server.endSession(r.PathValue("id"), input.Identity); err != nil {
		reply(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	reply(w, http.StatusOK, map[string]string{"state": "exited"})
}

func (server *Server) reap() {
	server.gatesMu.Lock()
	defer server.gatesMu.Unlock()
	for _, value := range server.registry.List(false) {
		current, err := server.identity(value.PID)
		if os.IsNotExist(err) || (err == nil && current != value.StartIdentity) {
			if err := server.endSession(value.ID, value.StartIdentity); err != nil {
				fmt.Fprintf(os.Stderr, "session cleanup %s: %v\n", value.ID, err)
			}
		}
	}
}

func (server *Server) fileReady(w http.ResponseWriter, r *http.Request) {
	server.gatesMu.Lock()
	defer server.gatesMu.Unlock()
	value, ok := server.registry.Get(r.PathValue("id"))
	if !ok || value.State != session.Running {
		reply(w, 409, map[string]string{"error": "no active session"})
		return
	}
	if value.SelectedProfile != nil {
		reply(w, 409, map[string]string{"error": "legacy file learning is unavailable for managed selections"})
		return
	}
	var input files.Context
	if err := decode(w, r, &input); err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	state, err := StateDirectory()
	if err != nil {
		reply(w, 500, map[string]string{"error": "state unavailable"})
		return
	}
	rel, err := filepath.Rel(filepath.Join(state, "runs"), input.Socket)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.Base(input.Socket) != "syd.sock" {
		reply(w, 400, map[string]string{"error": "IPC must be inside protected run authority"})
		return
	}
	input.Protected = append(input.Protected, filepath.Dir(state))
	project := value.Project
	if resolved, err := filepath.EvalSymlinks(project); err == nil {
		project = resolved
	}
	input.PolicyDirectory = filepath.Join(project, ".sydguard")
	if err := server.files.Register(value.ID, value.Name, input); err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	reply(w, 200, map[string]string{"status": "registered"})
}

func (server *Server) fileEvent(w http.ResponseWriter, r *http.Request) {
	var event files.Event
	if err := decode(w, r, &event); err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	server.files.Observe(r.PathValue("id"), event)
	reply(w, 200, map[string]string{"status": "observed"})
}

// endSession keeps the label reserved until owned teardown succeeds. gatesMu is held.
func (server *Server) endSession(id, identity string) error {
	value, ok := server.registry.Get(id)
	if !ok || value.StartIdentity != identity {
		return fmt.Errorf("unknown or stale session identity")
	}
	server.stopManagedLive(id)
	server.files.End(id)
	gate := server.gates[id]
	if gate != nil {
		gate.Close()
		delete(server.gates, id)
	}
	t := server.transparent[id]
	if t != nil {
		t.ending = true
		if t.gate != nil {
			t.gate.Close()
		}
		if t.dns != nil {
			t.dns.Close()
		}
		server.network.End(id)
		if t.runtime != nil {
			if err := t.runtime.Close(); err != nil {
				return fmt.Errorf("transparent cleanup failed: %w", err)
			}
		}
		delete(server.transparent, id)
	}
	server.network.End(id)
	return server.registry.Finish(id, identity)
}

func (server *Server) Close() {
	server.gatesMu.Lock()
	defer server.gatesMu.Unlock()
	server.closed = true
	for _, value := range server.registry.List(false) {
		if err := server.endSession(value.ID, value.StartIdentity); err != nil {
			fmt.Fprintf(os.Stderr, "session cleanup %s: %v\n", value.ID, err)
		}
	}
}

func decode(w http.ResponseWriter, r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing request data")
	}
	return nil
}

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
