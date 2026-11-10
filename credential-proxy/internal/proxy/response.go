package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

var errUnsafeResponse = errors.New("upstream response refused")

type responseSecrets struct{ patterns [][]byte }

func (s *responseSecrets) add(value string) {
	if value == "" {
		return
	}
	quoted, _ := json.Marshal(value)
	for _, pattern := range []string{value, url.QueryEscape(value), url.PathEscape(value),
		base64.StdEncoding.EncodeToString([]byte(value)), base64.RawStdEncoding.EncodeToString([]byte(value)),
		base64.URLEncoding.EncodeToString([]byte(value)), base64.RawURLEncoding.EncodeToString([]byte(value)),
		string(quoted[1 : len(quoted)-1])} {
		duplicate := false
		for _, existing := range s.patterns {
			if string(existing) == pattern {
				duplicate = true
				break
			}
		}
		if !duplicate {
			s.patterns = append(s.patterns, []byte(pattern))
		}
	}
}

func (s *responseSecrets) contains(data []byte) bool {
	for _, pattern := range s.patterns {
		if bytes.Contains(data, pattern) {
			return true
		}
	}
	return false
}

func (s *responseSecrets) checkResponse(resp *http.Response) error {
	refuse := func() error {
		resp.Body.Close()
		log.Print("event=response-refused status=blocked")
		return errUnsafeResponse
	}
	if s.contains([]byte(resp.Status)) || resp.StatusCode == http.StatusSwitchingProtocols {
		return refuse()
	}
	for name, values := range resp.Header {
		if s.contains([]byte(name)) {
			return refuse()
		}
		for _, value := range values {
			if s.contains([]byte(value)) {
				return refuse()
			}
		}
	}
	// Trailers and upgrades are alternative response channels. Do not forward
	// either from a credential-bearing destination.
	resp.Header.Del("Trailer")
	for name := range resp.Header {
		if strings.HasPrefix(strings.ToLower(name), "trailer:") {
			delete(resp.Header, name)
		}
	}
	resp.Trailer = nil
	encoding := resp.Header.Get("Content-Encoding")
	if encoding != "" && !strings.EqualFold(encoding, "identity") {
		return refuse()
	}
	if resp.StatusCode >= 400 {
		resp.Body.Close()
		body := "upstream request failed\n"
		resp.Body = io.NopCloser(strings.NewReader(body))
		resp.Header = http.Header{"Content-Type": {"text/plain; charset=utf-8"}}
		resp.ContentLength = int64(len(body))
		return nil
	}
	guard := &guardedBody{source: resp.Body, secrets: s, scrub: func() { resp.Trailer = nil }}
	// Inspect the initial read before ReverseProxy commits response headers.
	// Later streaming violations abort the connection without releasing a key.
	first := make([]byte, 32*1024)
	n, err := guard.Read(first)
	if err != nil && err != io.EOF {
		return refuse()
	}
	resp.Body = &prefixedBody{Reader: io.MultiReader(bytes.NewReader(first[:n]), guard), closer: guard}
	return nil
}

type prefixedBody struct {
	io.Reader
	closer io.Closer
}

func (b *prefixedBody) Close() error { return b.closer.Close() }

type guardedBody struct {
	source  io.ReadCloser
	secrets *responseSecrets
	pending []byte
	done    error
	scrub   func()
}

func (b *guardedBody) Close() error { return b.source.Close() }

func (b *guardedBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if b.secrets.contains(b.pending) {
			b.pending = nil
			b.done = errUnsafeResponse
			log.Print("event=response-refused status=blocked")
			return 0, b.done
		}
		// Hold only a suffix that could become a secret on the next read.
		// This bounds memory while preserving ordinary SSE flushes.
		hold := 0
		if b.done == nil {
			for _, pattern := range b.secrets.patterns {
				for n := min(len(b.pending), len(pattern)-1); n > hold; n-- {
					if bytes.Equal(b.pending[len(b.pending)-n:], pattern[:n]) {
						hold = n
						break
					}
				}
			}
		}
		if safe := len(b.pending) - hold; safe > 0 {
			n := copy(p, b.pending[:safe])
			b.pending = b.pending[n:]
			return n, nil
		}
		if b.done != nil {
			return 0, b.done
		}
		buffer := make([]byte, 32*1024)
		n, err := b.source.Read(buffer)
		if b.scrub != nil {
			b.scrub()
		}
		b.pending = append(b.pending, buffer[:n]...)
		b.done = err
	}
}
