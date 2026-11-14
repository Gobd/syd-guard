// Package api holds the small JSON-over-HTTP protocol shared by the guest
// daemon, the UI server and the CLI.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// EditReq is every rule/card action the UI can take.
type EditReq struct {
	VM      string `json:"vm"`
	Card    string `json:"card"`
	Scope   string `json:"scope"` // "global" or "rules"
	File    string `json:"file"`  // rules file for scope "rules"
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
}

type Func func(r *http.Request) (any, error)

// Handle registers a JSON endpoint: errors become {"error": ...} with 400.
func Handle(mux *http.ServeMux, pattern string, h Func) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		out, err := h(r)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, ErrUnauthorized) {
				status = http.StatusUnauthorized
			}
			w.WriteHeader(status)
			out = map[string]string{"error": err.Error()}
		}
		_ = json.NewEncoder(w).Encode(out)
	})
}

var ErrUnauthorized = errors.New("unauthorized: open the link from `sydguard ui`")

func Decode(r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<20)).Decode(v)
}

// UnixClient talks HTTP over a Unix socket.
func UnixClient(sock string, timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
}

// Call sends in as JSON (nil = GET) and decodes the reply into out.
func Call(client *http.Client, method, path string, in, out any) error {
	body := strings.NewReader("")
	if in != nil {
		data, _ := json.Marshal(in)
		body = strings.NewReader(string(data))
	}
	req, err := http.NewRequest(method, "http://sydguard"+path, body)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error string }
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return errors.New(e.Error)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Broadcaster fans out "something changed" to Server-Sent Event listeners.
type Broadcaster struct {
	mu   sync.Mutex
	subs map[chan struct{}]bool
}

func NewBroadcaster() *Broadcaster { return &Broadcaster{subs: map[chan struct{}]bool{}} }

func (b *Broadcaster) Notify() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (b *Broadcaster) Serve(w http.ResponseWriter, r *http.Request) { ServeEvents(w, r, b.Subscribe) }

func (b *Broadcaster) Subscribe() (chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	b.subs[ch] = true
	b.mu.Unlock()
	return ch, func() { b.mu.Lock(); delete(b.subs, ch); b.mu.Unlock() }
}

// ServeEvents streams "changed" SSE events from a subscription.
func ServeEvents(w http.ResponseWriter, r *http.Request, subscribe func() (chan struct{}, func())) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	ch, cancel := subscribe()
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = io.WriteString(w, "data: hello\n\n")
	flusher.Flush()
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ch:
			_, _ = io.WriteString(w, "data: changed\n\n")
		case <-tick.C:
			_, _ = io.WriteString(w, ": keepalive\n\n")
		}
		flusher.Flush()
	}
}

// WatchEvents follows an SSE stream, calling onEvent for every event, until
// the stream ends or ctx is done.
func WatchEvents(ctx context.Context, client *http.Client, path string, onEvent func()) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://sydguard"+path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 && strings.Contains(string(buf[:n]), "data:") {
			onEvent()
		}
		if err != nil {
			return err
		}
	}
}
