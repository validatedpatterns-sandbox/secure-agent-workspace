package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/ca"
	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/config"
	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/rewrite"
)

type Server struct {
	Store *config.Store
	CA    *ca.Authority
	// DialUpstream and Roots are set only by local tests. Production uses
	// cluster DNS and the image's system root store.
	DialUpstream func(context.Context, string, string) (net.Conn, error)
	Roots        *x509.CertPool
}

func (s *Server) Health(w http.ResponseWriter, _ *http.Request) {
	if err := s.CA.Ready(); err != nil {
		http.Error(w, "proxy CA unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, _, err := s.Store.Snapshot(); err != nil {
		http.Error(w, "credential binding unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || port != "443" || net.ParseIP(host) != nil || !validDNS(host) {
		http.Error(w, "invalid CONNECT target", http.StatusForbidden)
		return
	}
	host = strings.ToLower(host)
	policy, bindings, err := s.Store.Snapshot()
	if err != nil {
		http.Error(w, "credential binding unavailable", http.StatusBadGateway)
		return
	}
	if !config.Allowed(host, policy, bindings) {
		http.Error(w, "host not allowlisted", http.StatusForbidden)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT unavailable", http.StatusInternalServerError)
		return
	}
	client, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err = rw.Flush(); err != nil {
		return
	}
	reader := bufio.NewReaderSize(rw.Reader, 65541)
	sni, err := clientHelloSNI(reader)
	if err != nil || !strings.EqualFold(sni, host) {
		log.Printf("method=CONNECT host=%s path=- binding=- status=refused-sni", host)
		return
	}
	buffered := &bufferedConn{Conn: client, reader: reader}
	bound := false
	for _, b := range bindings {
		for _, pattern := range b.Hosts {
			if config.MatchHost(host, pattern) {
				bound = true
				break
			}
		}
	}
	if !bound {
		_ = client.SetDeadline(time.Time{})
		s.splice(buffered, host)
		return
	}
	cert, err := s.CA.Certificate(host)
	if err != nil {
		log.Printf("method=CONNECT host=%s path=- binding=- status=ca-unavailable", host)
		return
	}
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	tlsConn := tls.Server(buffered, &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
		Certificates: []tls.Certificate{*cert},
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	s.intercept(tlsConn, host)
}

func (s *Server) splice(client net.Conn, host string) {
	dial := s.DialUpstream
	if dial == nil {
		dial = (&net.Dialer{Timeout: 15 * time.Second}).DialContext
	}
	upstream, err := dial(context.Background(), "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		log.Printf("method=CONNECT host=%s path=- binding=- status=upstream-unavailable", host)
		return
	}
	defer upstream.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, client)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	wg.Wait()
	log.Printf("method=CONNECT host=%s path=- binding=- status=spliced", host)
}

func (s *Server) intercept(client net.Conn, host string) {
	dial := s.DialUpstream
	if dial == nil {
		dial = (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	transport := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, RootCAs: s.Roots},
		DialContext:     dial,
	}
	defer transport.CloseIdleConnections()
	reverse := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = net.JoinHostPort(host, "443")
			req.Host = host
		},
		Transport: transport, FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A CONNECT tunnel can carry multiple HTTP requests. Resolve mounted
		// Secrets for each one so a rotation takes effect on keepalive tunnels.
		policy, bindings, snapshotErr := s.Store.Snapshot()
		path := r.URL.Path // capture before rewriting: logging the new path could leak a key
		for _, b := range bindings {
			path = strings.ReplaceAll(path, b.Value, "***")
		}
		status := &statusWriter{ResponseWriter: w}
		binding := "-"
		defer func() {
			if status.code == 0 {
				status.code = http.StatusOK
			}
			log.Printf("method=%s host=%s path=%q binding=%s status=%d", r.Method, host, path, binding, status.code)
		}()
		if snapshotErr != nil || !config.Allowed(host, policy, bindings) {
			http.Error(status, "credential binding unavailable", http.StatusBadGateway)
			return
		}
		requestHost := r.Host
		if strings.Contains(requestHost, ":") {
			requestHost, _, _ = net.SplitHostPort(requestHost)
		}
		if !strings.EqualFold(requestHost, host) {
			http.Error(status, "Host does not match SNI", http.StatusBadGateway)
			return
		}
		var err error
		binding, err = rewrite.Request(r, host, policy.MarkerPrefix, bindings)
		if err != nil {
			if errors.Is(err, rewrite.ErrMarker) {
				http.Error(status, "unknown or unbound credential marker", http.StatusBadGateway)
			} else {
				http.Error(status, "invalid request", http.StatusBadGateway)
			}
			return
		}
		if binding == "" {
			binding = "-"
		}
		reverse.ServeHTTP(status, r)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 2 * time.Minute}
	_ = server.Serve(newSingleListener(client))
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func validDNS(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") || !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// A strict ClientHello peek lets us choose splice or interception without
// consuming any bytes. Fragmented or malformed ClientHellos fail closed.
func clientHelloSNI(r *bufio.Reader) (string, error) {
	header, err := r.Peek(5)
	if err != nil || header[0] != 22 {
		return "", errors.New("TLS ClientHello required")
	}
	n := int(binary.BigEndian.Uint16(header[3:5]))
	if n < 42 || n > 65535 {
		return "", errors.New("invalid TLS record")
	}
	record, err := r.Peek(5 + n)
	if err != nil {
		return "", err
	}
	p := record[5:]
	if p[0] != 1 || len(p) < 4+2+32 || int(p[1])<<16|int(p[2])<<8|int(p[3]) > len(p)-4 {
		return "", errors.New("invalid ClientHello")
	}
	p = p[4+2+32:]
	if len(p) < 1 || len(p) < 1+int(p[0]) {
		return "", errors.New("invalid session ID")
	}
	p = p[1+int(p[0]):]
	if len(p) < 2 || len(p) < 2+int(binary.BigEndian.Uint16(p[:2])) {
		return "", errors.New("invalid cipher suites")
	}
	p = p[2+int(binary.BigEndian.Uint16(p[:2])):]
	if len(p) < 1 || len(p) < 1+int(p[0]) {
		return "", errors.New("invalid compression methods")
	}
	p = p[1+int(p[0]):]
	if len(p) < 2 || len(p) < 2+int(binary.BigEndian.Uint16(p[:2])) {
		return "", errors.New("invalid extensions")
	}
	p = p[2 : 2+int(binary.BigEndian.Uint16(p[:2]))]
	for len(p) >= 4 {
		typ, size := binary.BigEndian.Uint16(p[:2]), int(binary.BigEndian.Uint16(p[2:4]))
		p = p[4:]
		if len(p) < size {
			return "", errors.New("truncated extension")
		}
		if typ == 0 {
			data := p[:size]
			if len(data) < 5 || len(data) < 2+int(binary.BigEndian.Uint16(data[:2])) || data[2] != 0 {
				return "", errors.New("invalid SNI")
			}
			nameLen := int(binary.BigEndian.Uint16(data[3:5]))
			if len(data) < 5+nameLen || !validDNS(string(data[5:5+nameLen])) {
				return "", errors.New("invalid SNI host")
			}
			return strings.ToLower(string(data[5 : 5+nameLen])), nil
		}
		p = p[size:]
	}
	return "", errors.New("SNI required")
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}
func (w *statusWriter) Write(p []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack unavailable")
}

type trackedConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

type singleListener struct {
	conn *trackedConn
	once sync.Once
	mu   sync.Mutex
	used bool
}

func newSingleListener(conn net.Conn) *singleListener {
	return &singleListener{conn: &trackedConn{Conn: conn, done: make(chan struct{})}}
}
func (l *singleListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.used {
		l.used = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.conn.done
	return nil, net.ErrClosed
}
func (l *singleListener) Close() error {
	l.once.Do(func() { _ = l.conn.Close() })
	return nil
}
func (l *singleListener) Addr() net.Addr { return l.conn.LocalAddr() }

// The stdlib ReverseProxy's WebSocket upgrade path needs http.Hijacker on the
// status writer; normal SSE responses need http.Flusher.
var _ http.Hijacker = (*statusWriter)(nil)
var _ http.Flusher = (*statusWriter)(nil)
