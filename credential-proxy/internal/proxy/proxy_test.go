package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/ca"
	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/config"
)

type fixture struct {
	proxy      *httptest.Server
	upstream   *httptest.Server
	client     *http.Client
	proxyCA    []byte
	secretPath string
	connects   atomic.Int32
}

func newFixture(t *testing.T, upstreamHost string, handler http.HandlerFunc) *fixture {
	t.Helper()
	root := t.TempDir()
	proxyCert, proxyKey, err := ca.Generate()
	if err != nil {
		t.Fatal(err)
	}
	upCert, upKey, err := ca.Generate()
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, value []byte) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, value, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	proxyAuthority := ca.New(write("proxy.crt", proxyCert), write("proxy.key", proxyKey))
	upAuthority := ca.New(write("up.crt", upCert), write("up.key", upKey))
	leaf, err := upAuthority.Certificate(upstreamHost)
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewUnstartedServer(handler)
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	secret := filepath.Join(root, "secrets", "inference")
	if err := os.MkdirAll(secret, 0700); err != nil {
		t.Fatal(err)
	}
	secretPath := write("secrets/inference/api_key", []byte("real-test-key"))
	write("secrets/inference/provider", []byte("nvidia"))
	policy := write("config.json", []byte(`{"markerPrefix":"saw-cred","allowHosts":["api.example.test","public.example.test"],"profiles":{"nvidia":["api.example.test"]},"bindings":[{"secret":"inference","key":"api_key","providers":["nvidia"]}]}`))
	store, err := config.New(policy, filepath.Join(root, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	upRoots := x509.NewCertPool()
	upRoots.AppendCertsFromPEM(upCert)
	s := &Server{Store: store, CA: proxyAuthority, Roots: upRoots,
		DialUpstream: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("tcp", upstream.Listener.Addr().String())
		}}
	f := &fixture{upstream: upstream, proxyCA: proxyCert, secretPath: secretPath}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			f.connects.Add(1)
		}
		s.ServeHTTP(w, r)
	}))
	t.Cleanup(proxy.Close)
	proxyURL, _ := url.Parse(proxy.URL)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(proxyCert)
	roots.AppendCertsFromPEM(upCert)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: false}, Timeout: 5 * time.Second}
	f.proxy, f.client = proxy, client
	return f
}

func TestRotationOnExistingTunnel(t *testing.T) {
	seen := make(chan string, 2)
	f := newFixture(t, "api.example.test", func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	request := func() {
		req, _ := http.NewRequest("GET", "https://api.example.test/v1", nil)
		req.Header.Set("Authorization", "Bearer saw-cred.inference.api_key")
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request status %d", resp.StatusCode)
		}
	}
	request()
	if got := <-seen; got != "Bearer real-test-key" {
		t.Fatalf("initial key %q", got)
	}
	if err := os.WriteFile(f.secretPath, []byte("rotated-test-key"), 0600); err != nil {
		t.Fatal(err)
	}
	request()
	if got := <-seen; got != "Bearer rotated-test-key" {
		t.Fatalf("rotated key %q", got)
	}
	if got := f.connects.Load(); got != 1 {
		t.Fatalf("rotation opened %d CONNECT tunnels; test did not exercise keepalive", got)
	}
	if err := os.Remove(f.secretPath); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "https://api.example.test/v1", nil)
	req.Header.Set("Authorization", "Bearer saw-cred.inference.api_key")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || f.connects.Load() != 1 {
		t.Fatalf("missing Secret status=%d connects=%d", resp.StatusCode, f.connects.Load())
	}
	select {
	case got := <-seen:
		t.Fatalf("missing Secret reached upstream: %q", got)
	default:
	}
}

func TestInterceptRewritesAndRefusesUnbound(t *testing.T) {
	seen := make(chan *http.Request, 2)
	f := newFixture(t, "api.example.test", func(w http.ResponseWriter, r *http.Request) {
		seen <- r
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
	marker := "saw-cred.inference.api_key"
	req, _ := http.NewRequest("GET", "https://api.example.test/v1/"+marker+"?key="+marker, nil)
	req.Header.Set("Authorization", "Bearer "+marker)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	up := <-seen
	if up.URL.Path != "/v1/real-test-key" || up.URL.Query().Get("key") != "real-test-key" || up.Header.Get("Authorization") != "Bearer real-test-key" {
		t.Fatalf("upstream did not receive rewritten request: path=%s, query=%s, auth=%s", up.URL.Path, up.URL.RawQuery, up.Header.Get("Authorization"))
	}
	bad, _ := http.NewRequest("GET", "https://api.example.test/v1", nil)
	bad.Header.Set("Authorization", "Bearer saw-cred.unknown.api_key")
	resp, err = f.client.Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Fatalf("unknown marker status %d", resp.StatusCode)
	}
	select {
	case <-seen:
		t.Fatal("unknown marker reached upstream")
	default:
	}
}

func TestHostMismatchAndSNIRefused(t *testing.T) {
	f := newFixture(t, "api.example.test", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	req, _ := http.NewRequest("GET", "https://api.example.test/v1", nil)
	req.Host = "wrong.example.test"
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Fatalf("Host mismatch status %d", resp.StatusCode)
	}
	conn, err := net.Dial("tcp", f.proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(conn, "CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\n\r\n")
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, "200") {
		t.Fatalf("CONNECT: %q %v", line, err)
	}
	// Consume the blank line before starting TLS on the same connection.
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "other.example.test", InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err == nil {
		t.Fatal("SNI mismatch was accepted")
	}
}

func TestSpliceAndStreaming(t *testing.T) {
	first := make(chan struct{})
	finish := make(chan struct{})
	f := newFixture(t, "public.example.test", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: first\n\n")
			w.(http.Flusher).Flush()
			close(first)
			<-finish
			_, _ = io.WriteString(w, "data: second\n\n")
			return
		}
		_, _ = io.WriteString(w, "spliced")
	})
	resp, err := f.client.Get("https://public.example.test/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "spliced" {
		t.Fatalf("splice body %q", body)
	}
	go func() {
		<-first
		time.Sleep(100 * time.Millisecond)
		close(finish)
	}()
	resp, err = f.client.Get("https://public.example.test/stream")
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	resp.Body.Close()
	if err != nil || line != "data: first\n" {
		t.Fatalf("stream line %q %v", line, err)
	}
}

func TestInterceptFlushesStreamingResponses(t *testing.T) {
	release := make(chan struct{})
	f := newFixture(t, "api.example.test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	resp, err := f.client.Get("https://api.example.test/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "data: first\n" {
		t.Fatalf("stream line %q %v", line, err)
	}
}
