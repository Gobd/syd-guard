package controller

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/network"
	"github.com/Gobd/syd-guard/internal/session"
)

func TestTransparentDenialDecisionAndLifecycle(t *testing.T) {
	token := strings.Repeat("a", 64)
	s, err := New(token)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.identity = func(int) (string, error) { return "test-start", nil }
	s.state = authorityFixture(t)
	run := filepath.Join(s.state, "runs", "run-test")
	if err = os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(run, "syd.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err = os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	var reject atomic.Bool
	var grants atomic.Int32
	var hold atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				line, _ := bufio.NewReader(conn).ReadString('\n')
				if line == "version\n" {
					_, _ = fmt.Fprintln(conn, `{"major":3,"minor":2,"version":"3.2"}`)
					return
				}
				grants.Add(1)
				if hold.Load() {
					close(entered)
					<-release
				}
				if reject.Load() {
					_, _ = fmt.Fprintln(conn, `{"err":1,"msg":"NO"}`)
				} else {
					_, _ = fmt.Fprintln(conn, `{"err":0,"msg":"ACK"}`)
				}
			}()
		}
	}()
	request := func(path string, body any) *httptest.ResponseRecorder {
		data, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", path, bytes.NewReader(data))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	register := func() session.Session {
		w := request("/api/sessions", Registration{Project: "/a/demo", Command: []string{"agent"}, PID: os.Getpid()})
		if w.Code != 201 {
			t.Fatalf("register: %s", w.Body)
		}
		var v session.Session
		if err = json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		s.transparent[v.ID] = &transparentSession{synthetic: network.NewSyntheticWithAllocator(s.allocator)}
		return v
	}
	a := register()
	b := register()
	if a.ID == b.ID {
		t.Fatal("IDs reused")
	}
	ready := func(id, path string) *httptest.ResponseRecorder {
		return request("/api/sessions/"+id+"/network-ready", map[string]string{"socket": path})
	}
	if w := ready(a.ID, socket); w.Code != 200 {
		t.Fatalf("ready %d %s", w.Code, w.Body)
	}
	if w := ready(b.ID, socket); w.Code != 409 {
		t.Fatalf("duplicate authority accepted: %d", w.Code)
	}
	runB := filepath.Join(s.state, "runs", "run-second")
	if err = os.MkdirAll(runB, 0o700); err != nil {
		t.Fatal(err)
	}
	socketB := filepath.Join(runB, "syd.sock")
	listenerB, err := net.Listen("unix", socketB)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listenerB.Close() }()
	if err = os.Chmod(socketB, 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, e := listenerB.Accept()
			if e != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = bufio.NewReader(c).ReadString('\n')
				_, _ = fmt.Fprintln(c, `{"major":3,"minor":2,"version":"3.2"}`)
			}()
		}
	}()
	if w := ready(b.ID, socketB); w.Code != 200 {
		t.Fatalf("second ready: %s", w.Body)
	}
	addr, err := s.transparent[a.ID].synthetic.Address("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	addrB, err := s.transparent[b.ID].synthetic.Address("api.example.com")
	if err != nil || addr == addrB {
		t.Fatal("sessions reused synthetic address", addr, addrB, err)
	}
	if w := request("/api/sessions/"+b.ID+"/network-event", NetworkEvent{Endpoint: addr.String() + ":8443"}); w.Code != 400 {
		t.Fatalf("cross-session denial replay: %d", w.Code)
	}
	if len(s.network.Pending()) != 0 {
		t.Fatal("DNS generated pending")
	}
	event := NetworkEvent{Record: json.RawMessage(fmt.Sprintf(`{"ctx":"access","cap":"net/connect","act":"deny","sys":"connect","addr":"tcp!%s!8443","ipv":4,"proto":"tcp"}`, addr))}
	if w := request("/api/sessions/"+a.ID+"/network-event", event); w.Code != 200 {
		t.Fatalf("event %s", w.Body)
	}
	pending := s.network.Pending()
	if len(pending) != 1 || pending[0].Target.Port != 8443 {
		t.Fatalf("bad pending %+v", pending)
	}
	decision := network.Decision{ID: pending[0].ID, Action: "allow", Scope: "run"}
	reject.Store(true)
	if err = s.decideNetwork(context.Background(), decision); err == nil {
		t.Fatal("failed ACK approved")
	}
	if len(s.network.Pending()) != 1 {
		t.Fatal("failed ACK removed pending")
	}
	reject.Store(false)
	if err = s.decideNetwork(context.Background(), decision); err != nil {
		t.Fatal(err)
	}
	if grants.Load() != 2 || len(s.network.Pending()) != 0 {
		t.Fatal("ACK not applied before approval")
	}
	if err = s.decideNetwork(context.Background(), decision); err == nil {
		t.Fatal("stale decision accepted")
	}
	serviceAddress, err := s.transparent[a.ID].synthetic.Address("examplelocal-api.sydguard.internal")
	if err != nil {
		t.Fatal(err)
	}
	otherAddress, err := s.transparent[a.ID].synthetic.Address("other.sydguard.internal")
	if err != nil {
		t.Fatal(err)
	}
	if w := request("/api/sessions/"+a.ID+"/network-event", NetworkEvent{Endpoint: otherAddress.String() + ":123"}); w.Code != 400 {
		t.Fatal("undeclared reserved service accepted")
	}
	s.transparent[a.ID].servicePort = 123
	s.transparent[a.ID].serviceHost = "examplelocal-api.sydguard.internal"
	if w := request("/api/sessions/"+a.ID+"/network-event", NetworkEvent{Endpoint: serviceAddress.String() + ":124"}); w.Code != 400 {
		t.Fatal("service port widened")
	}
	if w := request("/api/sessions/"+a.ID+"/network-event", NetworkEvent{Endpoint: serviceAddress.String() + ":123"}); w.Code != 200 {
		t.Fatalf("service grant %d %s", w.Code, w.Body)
	}
	serviceTarget, _ := network.Canonical("examplelocal-api.sydguard.internal", 123)
	if !s.network.Check(a.ID, a.Name, serviceTarget) || s.network.Check(b.ID, b.Name, serviceTarget) {
		t.Fatal("trusted service isolation")
	}
	if s.network.Check(b.ID, b.Name, pending[0].Target) {
		t.Fatal("cross-session grant")
	}
	if w := request("/api/sessions/"+a.ID+"/network-event", NetworkEvent{Endpoint: addr.String() + ":8444"}); w.Code != 200 {
		t.Fatalf("second event: %s", w.Body)
	}
	var second network.Pending
	for _, p := range s.network.Pending() {
		if p.SessionID == a.ID && p.Target.Port == 8444 {
			second = p
		}
	}
	if second.ID == "" {
		t.Fatal("missing second request")
	}
	hold.Store(true)
	decided := make(chan error, 1)
	go func() {
		decided <- s.decideNetwork(context.Background(), network.Decision{ID: second.ID, Action: "allow", Scope: "run"})
	}()
	<-entered
	completed := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		completed <- request("/api/sessions/"+a.ID+"/complete", map[string]string{"start_identity": a.StartIdentity})
	}()
	select {
	case <-completed:
		t.Fatal("session ended while grant in flight")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err = <-decided; err != nil {
		t.Fatal(err)
	}
	if w := <-completed; w.Code != 200 {
		t.Fatalf("complete: %s", w.Body)
	}
	if w := request("/api/sessions/"+a.ID+"/network-event", event); w.Code != 409 {
		t.Fatalf("event after end: %d", w.Code)
	}
	c := register()
	if c.Name != a.Name || c.ID == a.ID {
		t.Fatal("name reuse must use a new authority")
	}
	if err = s.decideNetwork(context.Background(), decision); err == nil {
		t.Fatal("old decision applied to reused name")
	}
	if s.network.Check(a.ID, a.Name, pending[0].Target) {
		t.Fatal("ended callback authorized")
	}
}

func TestTrustedServiceValidation(t *testing.T) {
	for _, v := range []Service{{"-bad", "127.0.0.1:123"}, {"UPPER", "127.0.0.1:123"}, {"other.name", "127.0.0.1:123"}, {"examplelocal-api", "localhost:123"}, {"examplelocal-api", "127.0.0.1:0123"}, {"examplelocal-api", "127.0.0.1:0"}} {
		if _, err := servicePort([]Service{v}); err == nil {
			t.Fatalf("accepted %+v", v)
		}
	}
	for _, name := range []string{"other", "examplelocal-api", "a1-b"} {
		if _, err := servicePort([]Service{{name, "127.0.0.1:123"}}); err != nil {
			t.Fatalf("valid service %s: %v", name, err)
		}
	}
	if _, err := servicePort([]Service{{"a", "127.0.0.1:1"}, {"b", "127.0.0.1:2"}}); err == nil {
		t.Fatal("accepted multiple services")
	}
	port, err := servicePort([]Service{{"examplelocal-api", "127.0.0.1:123"}})
	if err != nil || port != 123 {
		t.Fatal(port, err)
	}
}
