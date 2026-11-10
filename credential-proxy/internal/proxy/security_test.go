package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type captureBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *captureBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}
func (b *captureBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buffer.Bytes())
}

// Synthetic material only. Failure messages never dump a response or log.
func assertNoCredential(t *testing.T, data []byte, key string) {
	t.Helper()
	want := sha256.Sum256([]byte(key))
	for i := 0; i+len(key) <= len(data); i++ {
		if sha256.Sum256(data[i:i+len(key)]) == want {
			t.Fatal("credential digest matched captured output")
		}
	}
}

func TestCredentialReflectionFailsClosed(t *testing.T) {
	for _, surface := range []string{"body", "header", "status", "trailer", "query", "encoded", "error", "upgrade", "compressed", "informational"} {
		t.Run(surface, func(t *testing.T) {
			var logs captureBuffer
			old := log.Writer()
			log.SetOutput(&logs)
			defer log.SetOutput(old)
			f := newFixture(t, "api.example.test", func(w http.ResponseWriter, r *http.Request) {
				value := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				switch surface {
				case "informational":
					w.Header().Set("X-Echo", value)
					w.WriteHeader(103)
					w.Header().Del("X-Echo")
					w.WriteHeader(200)
					return
				case "compressed":
					w.Header().Set("Content-Encoding", "gzip")
				case "header":
					w.Header().Set("X-Echo", value)
				case "status":
					conn, _, _ := w.(http.Hijacker).Hijack()
					defer conn.Close()
					_, _ = io.WriteString(conn, "HTTP/1.1 200 "+value+"\r\nContent-Length: 0\r\n\r\n")
					return
				case "trailer":
					w.Header().Set("Trailer", "X-Echo")
					w.WriteHeader(200)
					w.Header().Set("X-Echo", value)
					return
				case "query":
					value = r.URL.Query().Get("key")
				case "encoded":
					value = base64.StdEncoding.EncodeToString([]byte(value))
				case "error":
					w.WriteHeader(500)
				case "upgrade":
					w.Header().Set("Connection", "Upgrade")
					w.Header().Set("Upgrade", "websocket")
					w.WriteHeader(101)
					return
				}
				if surface != "header" {
					_, _ = io.WriteString(w, value)
				}
			})
			req, _ := http.NewRequest("GET", "https://api.example.test/v1?key=saw-cred.inference.api_key", nil)
			req.Header.Set("Authorization", "Bearer saw-cred.inference.api_key")
			resp, err := f.client.Do(req)
			if err != nil {
				t.Fatal("request failed before response inspection")
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			var headers bytes.Buffer
			_ = resp.Header.Write(&headers)
			_ = resp.Trailer.Write(&headers)
			for _, data := range [][]byte{body, headers.Bytes(), logs.Bytes(), []byte(resp.Status)} {
				assertNoCredential(t, data, "real-test-key")
				assertNoCredential(t, data, base64.StdEncoding.EncodeToString([]byte("real-test-key")))
			}
			if surface != "trailer" && surface != "informational" && resp.StatusCode < 400 {
				t.Fatalf("unsafe upstream response accepted: status=%d", resp.StatusCode)
			}
		})
	}
}

func TestStreamNeverReleasesSplitCredential(t *testing.T) {
	for split := 1; split < len("real-test-key"); split++ {
		secrets := &responseSecrets{}
		secrets.add("real-test-key")
		reader := &guardedBody{source: io.NopCloser(io.MultiReader(
			strings.NewReader("safe event\nreal-test-key"[:len("safe event\n")+split]),
			strings.NewReader("real-test-key"[split:]))), secrets: secrets}
		data, err := io.ReadAll(reader)
		assertNoCredential(t, data, "real-test-key")
		if err == nil {
			t.Fatal("stream reflection accepted")
		}
	}
}

func TestDeniedCONNECTNeverResolvesOrDials(t *testing.T) {
	f := newFixture(t, "api.example.test", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	f.server.LookupIP = func(context.Context, string) ([]net.IPAddr, error) {
		t.Error("denied target reached DNS")
		return nil, errors.New("denied")
	}
	for _, target := range []string{"attacker.example.test:443", "169.254.169.254:443", "127.0.0.1:443", "[::1]:443", "api.example.test:8443"} {
		req, _ := http.NewRequest("CONNECT", f.proxy.URL, nil)
		req.Host = target
		resp, err := f.proxy.Client().Do(req)
		if err != nil {
			t.Fatal("CONNECT probe failed")
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("denied CONNECT status=%d", resp.StatusCode)
		}
	}
}

func TestBothPathsRejectPrivateDNSBeforeDial(t *testing.T) {
	for _, host := range []string{"api.example.test", "public.example.test"} {
		f := newFixture(t, host, func(w http.ResponseWriter, _ *http.Request) { t.Error("private address reached upstream") })
		f.server.LookupIP = func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}
		f.server.DialUpstream = func(context.Context, string, string) (net.Conn, error) {
			t.Error("private address reached dialer")
			return nil, errors.New("refused")
		}
		resp, err := f.client.Get("https://" + host + "/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != 502 {
				t.Fatal("private DNS target accepted")
			}
		}
	}
}

func TestUntrustedUpstreamTLSFailsClosed(t *testing.T) {
	f := newFixture(t, "api.example.test", func(w http.ResponseWriter, _ *http.Request) {
		t.Error("untrusted TLS upstream received an HTTP request")
	})
	f.server.Roots = x509.NewCertPool()
	req, _ := http.NewRequest("GET", "https://api.example.test/", nil)
	req.Header.Set("Authorization", "Bearer saw-cred.inference.api_key")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal("proxy did not return sanitized TLS failure")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 502 {
		t.Fatal("untrusted upstream certificate accepted")
	}
	assertNoCredential(t, body, "real-test-key")
}

func TestForwardedHeadersAreRemoved(t *testing.T) {
	f := newFixture(t, "api.example.test", func(w http.ResponseWriter, r *http.Request) {
		for name := range r.Header {
			if strings.EqualFold(name, "Forwarded") || strings.HasPrefix(strings.ToLower(name), "x-forwarded-") {
				t.Error("forwarded header reached credentialed upstream")
			}
		}
		w.WriteHeader(200)
	})
	req, _ := http.NewRequest("GET", "https://api.example.test/", nil)
	for _, name := range []string{"Forwarded", "X-Forwarded-Host", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Custom"} {
		req.Header.Set(name, "attacker.example.test")
	}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestTransportErrorDoesNotLogCredentialPath(t *testing.T) {
	var logs captureBuffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	f := newFixture(t, "api.example.test", func(w http.ResponseWriter, r *http.Request) {
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	})
	req, _ := http.NewRequest("GET", "https://api.example.test/real-test-key?key=saw-cred.inference.api_key", nil)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal("proxy failed to return sanitized transport error")
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assertNoCredential(t, body, "real-test-key")
	assertNoCredential(t, logs.Bytes(), "real-test-key")
	if resp.StatusCode != 502 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}
