// Package webui serves embedded approvals assets and an authenticated operator
// bridge. It never exposes a terminal or the controller master token.
package webui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Gobd/syd-guard/internal/controller"
)

//go:embed assets/*
var assets embed.FS

type Operator func(context.Context, string, string, []byte) ([]byte, error)

func Handler(host, token string, operate Operator) http.Handler {
	return HandlerWithAuth(host, func(provided string) bool {
		return subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
	}, operate)
}

// HandlerWithAuth permits a managed bridge to expire and rotate its UI token.
func HandlerWithAuth(host string, authorize func(string) bool, operate Operator) http.Handler {
	mux := http.NewServeMux()
	apiHandler := func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || !authorize(provided) {
			http.Error(w, "UI operator authorization required", http.StatusUnauthorized)
			return
		}
		allowed := controller.OperatorRoute(r.Method, r.URL.Path) && r.URL.Path != "/api/health"
		if !allowed || r.URL.RawQuery != "" || r.URL.RawPath != "" {
			http.Error(w, "unsupported UI route", http.StatusNotFound)
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024*1024+4096))
		if err != nil {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		output, err := operate(r.Context(), r.Method, r.URL.Path, data)
		if err != nil {
			if detail, ok := err.(interface {
				StatusCode() int
				ResponseBody() []byte
			}); ok && detail.StatusCode() >= 400 && detail.StatusCode() <= 599 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(detail.StatusCode())
				_, _ = w.Write(detail.ResponseBody())
				return
			}
			http.Error(w, "controller operation failed; refresh or inspect operator terminal", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(output)
	}
	mux.HandleFunc("GET /api/", apiHandler)
	mux.HandleFunc("POST /api/", apiHandler)
	mux.HandleFunc("PUT /api/", apiHandler)
	public, _ := fs.Sub(assets, "assets")
	mux.Handle("GET /", http.FileServer(http.FS(public)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != host {
			http.Error(w, "unexpected host", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+host {
			http.Error(w, "cross-origin access denied", http.StatusForbidden)
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "cross-site access denied", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		mux.ServeHTTP(w, r)
	})
}

func Serve(ctx context.Context, operate Operator, out io.Writer) error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return err
	}
	token := hex.EncodeToString(entropy[:])
	host := listener.Addr().String()
	server := NewServer(Handler(host, token, operate))
	if _, err := fmt.Fprintf(out, "Approvals UI: http://%s/#token=%s\nKeep this operator-only URL private. Ctrl-C closes the UI bridge.\n", host, token); err != nil {
		return err
	}
	return ServeListener(ctx, server, listener)
}

func NewServer(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
}

func ServeListener(ctx context.Context, server *http.Server, listener net.Listener) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
