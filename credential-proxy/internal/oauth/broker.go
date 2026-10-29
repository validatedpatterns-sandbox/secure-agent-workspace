// Package oauth keeps OAuth refresh material and short-lived access tokens
// outside workspace VMs. Its only input URL is the cluster-owned policy.
package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Material struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	RefreshToken string `json:"refreshToken"`
}

type Refresh struct {
	Strategy             string   `json:"strategy"`
	TokenURL             string   `json:"tokenURL"`
	RefreshBeforeSeconds int      `json:"refreshBeforeSeconds"`
	MaxLifetimeSeconds   int      `json:"maxLifetimeSeconds"`
	Material             Material `json:"material"`
}

// ReadMaterial checks presence without contacting the issuer. In particular,
// readiness must not depend on Google being available.
func ReadMaterial(spec Refresh, dir string) ([3]string, error) {
	var values [3]string
	for i, key := range []string{spec.Material.ClientID, spec.Material.ClientSecret, spec.Material.RefreshToken} {
		raw, err := os.ReadFile(filepath.Join(dir, key))
		if err != nil || strings.TrimSpace(string(raw)) == "" {
			return values, errors.New("refresh material missing or empty")
		}
		values[i] = strings.TrimSpace(string(raw))
	}
	return values, nil
}

type entry struct {
	mu                      sync.Mutex
	hash                    [32]byte
	token, rotated, failure string
	expires, retry          time.Time
}

type Broker struct {
	// Client and Roots allow TLS issuer servers in tests. Production uses a
	// direct transport, system roots, no redirects, and a 15 second timeout.
	Client  *http.Client
	Roots   *x509.CertPool
	Now     func() time.Time
	mu      sync.Mutex
	entries map[string]*entry
}

func (b *Broker) Token(ctx context.Context, id string, spec Refresh, dir string) (string, error) {
	b.mu.Lock()
	if b.entries == nil {
		b.entries = make(map[string]*entry)
	}
	e := b.entries[id]
	if e == nil {
		e = &entry{}
		b.entries[id] = e
	}
	b.mu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	values, err := ReadMaterial(spec, dir)
	if err != nil {
		return "", err
	}
	raw, _ := json.Marshal(struct {
		Spec   Refresh
		Values [3]string
	}{spec, values})
	hash := sha256.Sum256(raw)
	if hash != e.hash {
		e.hash, e.token, e.rotated, e.failure = hash, "", "", ""
		e.expires, e.retry = time.Time{}, time.Time{}
	}
	now := time.Now()
	if b.Now != nil {
		now = b.Now()
	}
	if e.token != "" && now.Before(e.expires.Add(-time.Duration(spec.RefreshBeforeSeconds)*time.Second)) {
		return e.token, nil
	}
	if now.Before(e.retry) {
		if e.token != "" && now.Before(e.expires) {
			return e.token, nil
		}
		return "", errors.New(e.failure)
	}
	refreshToken := values[2]
	if e.rotated != "" {
		refreshToken = e.rotated
	}
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {values[0]},
		"client_secret": {values[1]}, "refresh_token": {refreshToken}}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	binding := strings.SplitN(id, "/", 2)[0]
	fail := func(code string, transient bool) (string, error) {
		e.failure, e.retry = code, now.Add(60*time.Second)
		if transient && e.token != "" && now.Before(e.expires) {
			if e.expires.Before(e.retry) {
				e.retry = e.expires
			}
			log.Printf("event=oauth-refresh binding=%s status=failed error=%s transient=true cached_for=%d",
				binding, code, int(e.expires.Sub(now).Seconds()))
			return e.token, nil
		}
		e.token = ""
		log.Printf("event=oauth-refresh binding=%s status=failed error=%s transient=%t", binding, code, transient)
		return "", errors.New(code)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, spec.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fail("request_failed", true)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Transport: &http.Transport{Proxy: nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: b.Roots}}}
	if b.Client != nil {
		copy := *b.Client
		client = &copy
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return fail("request_failed", true)
	}
	defer resp.Body.Close()
	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fail("invalid_response", true)
	}
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Error        string `json:"error"`
	}
	if resp.StatusCode != http.StatusOK {
		// A fixed vocabulary prevents arbitrary issuer text (including an
		// error_description containing secrets) from entering logs or errors.
		_ = json.Unmarshal(rawBody, &body)
		code := "token_endpoint_error"
		switch body.Error {
		case "invalid_grant", "invalid_client", "invalid_request", "unauthorized_client",
			"unsupported_grant_type", "invalid_scope", "temporarily_unavailable", "server_error":
			code = body.Error
		}
		transient := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 ||
			body.Error == "temporarily_unavailable" || body.Error == "server_error"
		return fail(code, transient)
	}
	if err := json.Unmarshal(rawBody, &body); err != nil {
		return fail("invalid_response", true)
	}
	if body.AccessToken == "" || strings.ContainsAny(body.AccessToken, "\r\n") || body.ExpiresIn <= 0 {
		return fail("invalid_response", true)
	}
	lifetime := min(body.ExpiresIn, int64(spec.MaxLifetimeSeconds))
	e.token, e.expires, e.failure, e.retry = body.AccessToken, now.Add(time.Duration(lifetime)*time.Second), "", time.Time{}
	rotated := body.RefreshToken != ""
	if rotated {
		e.rotated = body.RefreshToken
	}
	log.Printf("event=oauth-refresh binding=%s status=ok expires_in=%d rotated=%t", binding, lifetime, rotated)
	return e.token, nil
}
