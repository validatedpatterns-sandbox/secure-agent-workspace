package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRefreshCacheConcurrencyRotationAndRedaction(t *testing.T) {
	dir := t.TempDir()
	material := map[string]string{"client_id": "client-ID-private", "client_secret": "client-secret-private", "refresh_token": "original-refresh-private"}
	for k, v := range material {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var posts atomic.Int32
	var invalid atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := posts.Add(1)
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("wrong method or content type")
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		expected := "original-refresh-private"
		if n > 1 {
			expected = "rotated-refresh-private"
		}
		if n == 3 {
			expected = "changed-refresh-private"
		}
		if len(r.PostForm) != 4 || r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("client_id") != material["client_id"] || r.Form.Get("client_secret") != material["client_secret"] || r.Form.Get("refresh_token") != expected {
			t.Error("incorrect OAuth form")
		}
		w.Header().Set("Content-Type", "application/json")
		if invalid.Load() {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"invalid_grant","error_description":"client-secret-private original-refresh-private"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("minted-access-private-%d", n), "expires_in": 7200, "refresh_token": "rotated-refresh-private"})
	}))
	defer server.Close()
	now := time.Unix(1700000000, 0)
	b := &Broker{Client: server.Client(), Now: func() time.Time { return now }}
	spec := Refresh{Strategy: "oauth2_refresh_token", TokenURL: server.URL, RefreshBeforeSeconds: 300, MaxLifetimeSeconds: 3600, Material: Material{"client_id", "client_secret", "refresh_token"}}
	var output bytes.Buffer
	old := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(old)
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := b.Token(context.Background(), "gmail", spec, dir)
			if err != nil || token != "minted-access-private-1" {
				t.Error("concurrent refresh failed")
			}
		}()
	}
	wg.Wait()
	if posts.Load() != 1 {
		t.Fatalf("got %d posts for 50 callers", posts.Load())
	}
	now = now.Add(3299 * time.Second)
	if _, err := b.Token(context.Background(), "gmail", spec, dir); err != nil || posts.Load() != 1 {
		t.Fatal("cache hit failed")
	}
	now = now.Add(time.Second)
	if token, err := b.Token(context.Background(), "gmail", spec, dir); err != nil || token != "minted-access-private-2" {
		t.Fatal("expiry refresh failed")
	}
	if err := os.WriteFile(filepath.Join(dir, "refresh_token"), []byte("changed-refresh-private"), 0600); err != nil {
		t.Fatal(err)
	}
	if token, err := b.Token(context.Background(), "gmail", spec, dir); err != nil || token != "minted-access-private-3" {
		t.Fatal("material change did not refresh")
	}
	invalid.Store(true)
	now = now.Add(3300 * time.Second)
	for range 2 {
		if _, err := b.Token(context.Background(), "gmail", spec, dir); err == nil || err.Error() != "invalid_grant" {
			t.Fatal("expected sanitized invalid_grant")
		}
	}
	if posts.Load() != 4 {
		t.Fatal("failed refresh was not backed off")
	}
	now = now.Add(59 * time.Second)
	_, _ = b.Token(context.Background(), "gmail", spec, dir)
	if posts.Load() != 4 {
		t.Fatal("retried before backoff elapsed")
	}
	invalid.Store(false)
	now = now.Add(time.Second)
	if _, err := b.Token(context.Background(), "gmail", spec, dir); err != nil || posts.Load() != 5 {
		t.Fatal("did not recover after backoff")
	}
	for _, secret := range []string{"client-ID-private", "client-secret-private", "original-refresh-private", "rotated-refresh-private", "changed-refresh-private", "minted-access-private"} {
		if strings.Contains(output.String(), secret) {
			t.Fatal("secret leaked to logs")
		}
	}
	if !strings.Contains(output.String(), "status=failed error=invalid_grant") || !strings.Contains(output.String(), "rotated=true") {
		t.Fatal("missing refresh audit records")
	}
}

func TestTransientEarlyRefreshServesTheValidToken(t *testing.T) {
	cases := []struct {
		name, code string
		status     int
		body       string
		drop       bool
	}{
		{name: "html 503", code: "token_endpoint_error", status: http.StatusServiceUnavailable, body: "<html>busy</html>"},
		{name: "server error", code: "server_error", status: http.StatusInternalServerError, body: `{"error":"server_error"}`},
		{name: "rate limit", code: "token_endpoint_error", status: http.StatusTooManyRequests, body: `{"error":"rate_limit"}`},
		{name: "temporarily unavailable", code: "temporarily_unavailable", status: http.StatusBadRequest, body: `{"error":"temporarily_unavailable"}`},
		{name: "dropped connection", code: "request_failed", drop: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for key, value := range map[string]string{
				"client_id": "client-private", "client_secret": "secret-private", "refresh_token": "refresh-private",
			} {
				if err := os.WriteFile(filepath.Join(dir, key), []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var failed atomic.Bool
			var posts atomic.Int32
			var successes atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				if failed.Load() {
					if tc.drop {
						h, ok := w.(http.Hijacker)
						if !ok {
							t.Error("test server does not support hijacking")
							return
						}
						conn, _, err := h.Hijack()
						if err == nil {
							_ = conn.Close()
						}
						return
					}
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.body)
					return
				}
				n := successes.Add(1)
				_, _ = fmt.Fprintf(w, `{"access_token":"minted-%c","expires_in":3600}`, 'A'+rune(n-1))
			}))
			defer server.Close()
			base := time.Unix(1700000000, 0)
			now := base
			broker := &Broker{Client: server.Client(), Now: func() time.Time { return now }}
			spec := Refresh{Strategy: "oauth2_refresh_token", TokenURL: server.URL,
				RefreshBeforeSeconds: 300, MaxLifetimeSeconds: 3600,
				Material: Material{"client_id", "client_secret", "refresh_token"}}
			var output bytes.Buffer
			old := log.Writer()
			log.SetOutput(&output)
			defer log.SetOutput(old)

			if token, err := broker.Token(context.Background(), "gmail", spec, dir); err != nil || token != "minted-A" {
				t.Fatalf("initial token: %q %v", token, err)
			}
			failed.Store(true)
			now = base.Add(3300 * time.Second)
			if token, err := broker.Token(context.Background(), "gmail", spec, dir); err != nil || token != "minted-A" || posts.Load() != 2 {
				t.Fatalf("early transient refresh: token=%q err=%v posts=%d", token, err, posts.Load())
			}
			now = base.Add(3330 * time.Second)
			if token, err := broker.Token(context.Background(), "gmail", spec, dir); err != nil || token != "minted-A" || posts.Load() != 2 {
				t.Fatalf("transient backoff: token=%q err=%v posts=%d", token, err, posts.Load())
			}
			now = base.Add(3361 * time.Second)
			if token, err := broker.Token(context.Background(), "gmail", spec, dir); err != nil || token != "minted-A" || posts.Load() != 3 {
				t.Fatalf("transient retry: token=%q err=%v posts=%d", token, err, posts.Load())
			}
			now = base.Add(3600 * time.Second)
			if token, err := broker.Token(context.Background(), "gmail", spec, dir); err == nil || token != "" || err.Error() != tc.code || posts.Load() != 4 {
				t.Fatalf("expired token: token=%q err=%v posts=%d", token, err, posts.Load())
			}
			failed.Store(false)
			now = base.Add(3661 * time.Second)
			if token, err := broker.Token(context.Background(), "gmail", spec, dir); err != nil || token != "minted-B" || posts.Load() != 5 {
				t.Fatalf("recovery: token=%q err=%v posts=%d", token, err, posts.Load())
			}
			if !strings.Contains(output.String(), "transient=true") {
				t.Fatal("missing transient refresh audit")
			}
			for _, secret := range []string{"client-private", "secret-private", "refresh-private", "minted-A", "minted-B"} {
				if strings.Contains(output.String(), secret) {
					t.Fatalf("secret leaked to logs: %s", secret)
				}
			}
		})
	}
}

func TestPermanentEarlyRefreshFailsClosed(t *testing.T) {
	cases := []struct {
		name, body, code string
		status           int
	}{
		{name: "invalid grant", status: http.StatusBadRequest, body: `{"error":"invalid_grant"}`, code: "invalid_grant"},
		{name: "invalid client", status: http.StatusBadRequest, body: `{"error":"invalid_client"}`, code: "invalid_client"},
		{name: "unauthorized client", status: http.StatusBadRequest, body: `{"error":"unauthorized_client"}`, code: "unauthorized_client"},
		{name: "bare unauthorized", status: http.StatusUnauthorized, body: "", code: "token_endpoint_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for key, value := range map[string]string{"client_id": "client", "client_secret": "secret", "refresh_token": "refresh"} {
				if err := os.WriteFile(filepath.Join(dir, key), []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var failed atomic.Bool
			var posts atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				posts.Add(1)
				if failed.Load() {
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.body)
					return
				}
				_, _ = io.WriteString(w, `{"access_token":"minted-A","expires_in":3600}`)
			}))
			defer server.Close()
			base := time.Unix(1700000000, 0)
			now := base
			broker := &Broker{Client: server.Client(), Now: func() time.Time { return now }}
			spec := Refresh{Strategy: "oauth2_refresh_token", TokenURL: server.URL,
				RefreshBeforeSeconds: 300, MaxLifetimeSeconds: 3600,
				Material: Material{"client_id", "client_secret", "refresh_token"}}
			if token, err := broker.Token(context.Background(), "gmail", spec, dir); err != nil || token != "minted-A" {
				t.Fatalf("initial token: %q %v", token, err)
			}
			failed.Store(true)
			now = base.Add(3300 * time.Second)
			if token, err := broker.Token(context.Background(), "gmail", spec, dir); err == nil || token != "" || err.Error() != tc.code || posts.Load() != 2 {
				t.Fatalf("permanent failure: token=%q err=%v posts=%d", token, err, posts.Load())
			}
			now = base.Add(3330 * time.Second)
			if token, err := broker.Token(context.Background(), "gmail", spec, dir); err == nil || token != "" || err.Error() != tc.code || posts.Load() != 2 {
				t.Fatalf("permanent backoff: token=%q err=%v posts=%d", token, err, posts.Load())
			}
		})
	}
}

func TestIssuerRedirectIsNotFollowed(t *testing.T) {
	dir := t.TempDir()
	for _, k := range []string{"client_id", "client_secret", "refresh_token"} {
		if err := os.WriteFile(filepath.Join(dir, k), []byte("private"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var leaked atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer target.Close()
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(307)
	}))
	defer issuer.Close()
	b := &Broker{Client: issuer.Client()}
	_, err := b.Token(context.Background(), "gmail", Refresh{TokenURL: issuer.URL, MaxLifetimeSeconds: 3600, Material: Material{"client_id", "client_secret", "refresh_token"}}, dir)
	if err == nil || leaked.Load() != 0 {
		t.Fatal("refresh redirected credential material")
	}
}
