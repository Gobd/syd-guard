package controller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLearningRegistrationRejectsOldProtocol3Controller(t *testing.T) {
	posts := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			w.WriteHeader(400)
			return
		}
		_, _ = w.Write([]byte(`{"service":"sydguard","protocol":3}`))
	})
	test := httptest.NewServer(handler)
	defer test.Close()
	client := &Client{token: strings.Repeat("a", 64), http: &http.Client{Transport: rewriteHost{base: test.Client().Transport, host: test.URL}}}
	if _, err := client.RegisterTransparentLearning(context.Background(), "/project", "", []string{"true"}); !errors.Is(err, ErrLearningUnsupported) || posts != 0 {
		t.Fatalf("old controller: %v posts=%d", err, posts)
	}
}

type rewriteHost struct {
	base http.RoundTripper
	host string
}

func (t rewriteHost) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(t.host, "http://")
	return t.base.RoundTrip(clone)
}
