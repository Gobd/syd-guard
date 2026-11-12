package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Gobd/syd-guard/internal/files"
	"github.com/Gobd/syd-guard/internal/session"
)

var ErrProtocolMismatch = errors.New("incompatible controller protocol; stop the existing daemon explicitly before upgrading")

// OperatorError preserves bounded controller errors across operator transports.
type OperatorError struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

func (e *OperatorError) Error() string {
	return fmt.Sprintf("controller operation failed: HTTP %d", e.Status)
}
func (e *OperatorError) StatusCode() int      { return e.Status }
func (e *OperatorError) ResponseBody() []byte { return e.Body }

type Client struct {
	directory, token string
	http             *http.Client
}

func OpenClient(directory string) (*Client, error) {
	if err := privateState(directory); err != nil {
		return nil, err
	}
	token, err := operatorToken(directory)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(directory, "controller.sock"))
	}}
	return &Client{directory: directory, token: token, http: &http.Client{Transport: transport, Timeout: 120 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (client *Client) Close() { client.http.CloseIdleConnections() }

func (client *Client) Health(ctx context.Context) error {
	var health struct {
		Service  string `json:"service"`
		Protocol int    `json:"protocol"`
	}
	if err := client.request(ctx, "GET", "/api/health", nil, &health); err != nil {
		return err
	}
	if health.Service != "sydguard" || health.Protocol != 3 {
		return ErrProtocolMismatch
	}
	return nil
}

// Ensure starts the trusted executable only after checking for an existing
// compatible daemon. Its nonblocking lock serializes simultaneous starts.
func (client *Client) Ensure(ctx context.Context, executable string) error {
	if err := client.Health(ctx); err == nil {
		return nil
	} else if errors.Is(err, ErrProtocolMismatch) {
		return err
	}
	logPath := filepath.Join(client.directory, "controller.log")
	if info, err := os.Lstat(logPath); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("unsafe controller log")
		}
		if err := owned(info); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	log, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // validated operator-owned log inside private authority directory
	if err != nil {
		return err
	}
	command := exec.Command(executable, "serve", "--state", client.directory) //nolint:gosec // caller's own trusted executable, fixed daemon argv; no shell or workload args
	detach(command)
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		_ = log.Close()
		return err
	}
	_ = log.Close()
	go func() { _ = command.Wait() }()
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(40 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := client.Health(deadline); err == nil {
			return nil
		} else if errors.Is(err, ErrProtocolMismatch) {
			return err
		}
		select {
		case <-deadline.Done():
			return fmt.Errorf("controller startup failed; inspect %s: %w", logPath, deadline.Err())
		case <-ticker.C:
		}
	}
}

func (client *Client) Register(ctx context.Context, project, name string, argv []string) (session.Session, error) {
	return client.RegisterProxy(ctx, project, name, argv, false)
}

func (client *Client) RegisterProxy(ctx context.Context, project, name string, argv []string, proxy bool) (session.Session, error) {
	var registered session.Session
	err := client.request(ctx, "POST", "/api/sessions", map[string]any{"project": project, "name": name, "command": argv, "pid": os.Getpid(), "network_proxy": proxy}, &registered)
	return registered, err
}

// RegisterTransparent starts an isolated session. Services are explicit trusted launcher inputs.
func (client *Client) RegisterTransparent(ctx context.Context, project, name string, argv []string, services []Service) (session.Session, error) {
	var value session.Session
	err := client.request(ctx, "POST", "/api/sessions", Registration{Project: project, Name: name, Command: argv, PID: os.Getpid(), Transparent: true, Services: services}, &value)
	return value, err
}

func (client *Client) NetworkReady(ctx context.Context, id, socket string) error {
	return client.request(ctx, "POST", "/api/sessions/"+id+"/network-ready", map[string]string{"socket": socket}, nil)
}

func (client *Client) NetworkEvent(ctx context.Context, id string, event NetworkEvent) error {
	return client.request(ctx, "POST", "/api/sessions/"+id+"/network-event", event, nil)
}

// OperatorRoute permits only approvals and bounded profile operations.
func OperatorRoute(method, path string) bool {
	if method == "GET" && (path == "/api/health" || path == "/api/sessions" || path == "/api/network/pending" || path == "/api/network/rules" || path == "/api/files/pending" || path == "/api/profiles") || method == "POST" && (path == "/api/network/decisions" || path == "/api/files/decisions") {
		return true
	}
	parts := strings.Split(path, "/")
	if len(parts) == 4 && parts[0] == "" && parts[1] == "api" && parts[2] == "profiles" && validProfileID(parts[3]) {
		return method == "GET" || method == "PUT"
	}
	return len(parts) == 5 && parts[0] == "" && parts[1] == "api" && parts[2] == "profiles" && validProfileID(parts[3]) && parts[4] == "reload" && method == "POST"
}

// Operate exposes only approval/read routes, not raw Syd commands or launch APIs.
func (client *Client) Operate(ctx context.Context, method, path string, input any) (json.RawMessage, error) {
	if !OperatorRoute(method, path) {
		return nil, fmt.Errorf("unsupported operator route")
	}
	var output json.RawMessage
	err := client.request(ctx, method, path, input, &output)
	return output, err
}

func (client *Client) FileReady(ctx context.Context, id string, value files.Context) error {
	return client.request(ctx, "POST", "/api/sessions/"+id+"/files", value, nil)
}

func (client *Client) FileEvent(ctx context.Context, id string, event files.Event) error {
	return client.request(ctx, "POST", "/api/sessions/"+id+"/events", event, nil)
}

func (client *Client) Complete(ctx context.Context, value session.Session) error {
	return client.request(ctx, "POST", "/api/sessions/"+value.ID+"/complete", map[string]string{"start_identity": value.StartIdentity}, nil)
}

func (client *Client) Sessions(ctx context.Context, history bool) ([]session.Session, error) {
	var values []session.Session
	path := "/api/sessions"
	if history {
		path += "?history=true"
	}
	err := client.request(ctx, "GET", path, nil, &values)
	return values, err
}

func (client *Client) request(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://sydguard"+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		return fmt.Errorf("controller request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		if !json.Valid(data) {
			data = []byte(`{"error":"controller operation failed","code":"unavailable"}`)
		}
		return &OperatorError{Status: response.StatusCode, Body: data}
	}
	if output != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 2*1024*1024)).Decode(output)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return err
}
