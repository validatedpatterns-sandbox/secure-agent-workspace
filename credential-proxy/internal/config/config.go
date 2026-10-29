package config

import (
	"context"
	"encoding/json"

	"errors"
	"fmt"
	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/oauth"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// The ConfigMap contains policy, never credential values. The projected Secret
// files are read again for each request so kubelet's atomic symlink swaps are
// visible without restarting the proxy.
type Policy struct {
	MarkerPrefix string              `json:"markerPrefix"`
	AllowHosts   []string            `json:"allowHosts"`
	Profiles     map[string][]string `json:"profiles"`
	Bindings     []Binding           `json:"bindings"`
}

type Refresh = oauth.Refresh

type Binding struct {
	Refresh   *Refresh `json:"refresh,omitempty"`
	Secret    string   `json:"secret"`
	Key       string   `json:"key"`
	Providers []string `json:"providers"`
}

type Resolved struct {
	Token  func(context.Context) (string, error)
	Marker string
	Secret string
	Key    string
	Hosts  []string
	Value  string
}

type Store struct {
	Broker     *oauth.Broker
	path       string
	secretsDir string
	mu         sync.RWMutex
	policy     Policy
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$|^[a-z0-9]$`)
var keyRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func New(path, secretsDir string) (*Store, error) {
	s := &Store{path: path, secretsDir: secretsDir, Broker: &oauth.Broker{}}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Reload() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("decode policy: %w", err)
	}
	if p.MarkerPrefix == "" || !keyRE.MatchString(p.MarkerPrefix) {
		return errors.New("invalid marker prefix")
	}
	if len(p.AllowHosts) == 0 || len(p.Bindings) == 0 {
		return errors.New("allowHosts and bindings are required")
	}
	for _, h := range p.AllowHosts {
		if !validPattern(h) {
			return fmt.Errorf("invalid allow host %q", h)
		}
	}
	for typ, hosts := range p.Profiles {
		if !nameRE.MatchString(typ) {
			return fmt.Errorf("invalid provider type %q", typ)
		}
		for _, h := range hosts {
			if !validPattern(h) {
				return fmt.Errorf("invalid profile host %q", h)
			}
		}
	}
	seen := map[string]bool{}
	for _, b := range p.Bindings {
		if !nameRE.MatchString(b.Secret) || !keyRE.MatchString(b.Key) || len(b.Providers) == 0 {
			return errors.New("invalid credential binding")
		}
		if b.Refresh != nil {
			spec := b.Refresh
			u, err := url.Parse(spec.TokenURL)
			if err != nil || u.Scheme != "https" || !validDNSHost(u.Hostname()) ||
				strings.Contains(u.Hostname(), "*") || u.User != nil || u.RawQuery != "" ||
				u.ForceQuery || u.Fragment != "" || strings.Contains(spec.TokenURL, "#") ||
				(u.Port() != "" && u.Port() != "443") ||
				spec.Strategy != "oauth2_refresh_token" || len(b.Providers) != 1 ||
				spec.RefreshBeforeSeconds < 0 || spec.RefreshBeforeSeconds >= spec.MaxLifetimeSeconds ||
				spec.MaxLifetimeSeconds > 86400 {
				return errors.New("invalid refresh binding")
			}
			allowed := false
			for _, h := range p.AllowHosts {
				if MatchHost(u.Hostname(), h) {
					allowed = true
				}
			}
			if !allowed {
				return errors.New("refresh token host is not allowlisted")
			}
			for _, key := range []string{spec.Material.ClientID, spec.Material.ClientSecret, spec.Material.RefreshToken} {
				if !keyRE.MatchString(key) || key == "." || key == ".." {
					return errors.New("invalid refresh material key")
				}
			}
		}
		marker := p.MarkerPrefix + "." + b.Secret + "." + b.Key
		if seen[marker] {
			return fmt.Errorf("duplicate credential binding %s", marker)
		}
		seen[marker] = true
		for _, typ := range b.Providers {
			if _, ok := p.Profiles[typ]; !ok {
				// A custom URL may be the only endpoint of this provider.
				if !nameRE.MatchString(typ) {
					return fmt.Errorf("invalid provider type %q", typ)
				}
			}
		}
	}
	s.mu.Lock()
	s.policy = p
	s.mu.Unlock()
	return nil
}

func (s *Store) Prefix() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy.MarkerPrefix
}

func (s *Store) Snapshot() (Policy, []Resolved, error) {
	s.mu.RLock()
	p := s.policy
	s.mu.RUnlock()
	resolved := make([]Resolved, 0, len(p.Bindings))
	for _, b := range p.Bindings {
		base := filepath.Join(s.secretsDir, b.Secret)
		var value []byte
		var err error
		if b.Refresh != nil {
			_, err = oauth.ReadMaterial(*b.Refresh, base)
		} else {
			value, err = os.ReadFile(filepath.Join(base, b.Key))
		}
		if err != nil {
			return p, nil, fmt.Errorf("Secret %s key %s is missing or empty", b.Secret, b.Key)
		}
		providerRaw, _ := os.ReadFile(filepath.Join(base, "provider"))
		typ := strings.TrimSpace(string(providerRaw))
		types := b.Providers
		if typ != "" {
			permitted := false
			for _, candidate := range b.Providers {
				if candidate == typ {
					permitted = true
				}
			}
			if !permitted {
				return p, nil, fmt.Errorf("Secret %s has no allowed provider type", b.Secret)
			}
			types = []string{typ}
		}
		// With no provider discriminator the cluster-owned binding permits
		// every listed type; an explicit provider narrows that host set.
		hosts := []string{}
		seen := map[string]bool{}
		for _, candidate := range types {
			for _, host := range p.Profiles[candidate] {
				if !seen[host] {
					hosts = append(hosts, host)
					seen[host] = true
				}
			}
		}
		plainHTTP := false
		urlRaw, _ := os.ReadFile(filepath.Join(base, "url"))
		if custom := strings.TrimSpace(string(urlRaw)); custom != "" {
			u, err := url.Parse(custom)
			if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
				(u.Scheme != "https" && u.Scheme != "http") {
				return p, nil, fmt.Errorf("Secret %s has an invalid url", b.Secret)
			}
			if u.Scheme == "https" {
				if (u.Port() != "" && u.Port() != "443") || !validPattern(strings.ToLower(u.Hostname())) ||
					strings.Contains(u.Hostname(), "*") {
					return p, nil, fmt.Errorf("Secret %s has an invalid HTTPS host or port", b.Secret)
				}
				hosts = append(hosts, strings.ToLower(u.Hostname()))
			} else {
				plainHTTP = true
			}
		}
		// Keyless HTTP bypasses interception. It needs no resolved key and
		// must not prevent the installer from starting the sandbox gateway.
		if plainHTTP && (len(hosts) == 0 || strings.TrimSpace(string(value)) == "") {
			continue
		}
		if b.Refresh == nil && strings.TrimSpace(string(value)) == "" {
			return p, nil, fmt.Errorf("Secret %s key %s is missing or empty", b.Secret, b.Key)
		}
		if len(hosts) == 0 {
			return p, nil, fmt.Errorf("Secret %s has no bound hosts", b.Secret)
		}
		var token func(context.Context) (string, error)
		if b.Refresh != nil {
			if s.Broker == nil {
				return p, nil, errors.New("refresh broker unavailable")
			}
			spec, id := *b.Refresh, b.Secret+"/"+b.Key
			token = func(ctx context.Context) (string, error) { return s.Broker.Token(ctx, id, spec, base) }
		}
		resolved = append(resolved, Resolved{Token: token,
			Marker: p.MarkerPrefix + "." + b.Secret + "." + b.Key,
			Secret: b.Secret, Key: b.Key, Hosts: hosts, Value: strings.TrimSpace(string(value)),
		})
	}
	return p, resolved, nil
}

func validPattern(host string) bool {
	if strings.Count(host, "*") > 1 || strings.ContainsAny(host, "/:@ ") || net.ParseIP(host) != nil {
		return false
	}
	if strings.Contains(host, "*") {
		parts := strings.Split(host, ".")
		if len(parts) < 3 || !strings.Contains(parts[0], "*") {
			return false
		}
	}
	return host == strings.ToLower(host) && strings.Contains(host, ".")
}

// MatchHost uses one DNS label for *, like OpenShell's endpoint matching.
func MatchHost(host, pattern string) bool {
	host, pattern = strings.ToLower(host), strings.ToLower(pattern)
	if host == pattern {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return false
	}
	h, p := strings.Split(host, "."), strings.Split(pattern, ".")
	if len(h) != len(p) {
		return false
	}
	for i := range h {
		if !strings.Contains(p[i], "*") {
			if h[i] != p[i] {
				return false
			}
			continue
		}
		parts := strings.Split(p[i], "*")
		if len(parts) != 2 || !strings.HasPrefix(h[i], parts[0]) || !strings.HasSuffix(h[i], parts[1]) || len(h[i]) < len(parts[0])+len(parts[1]) {
			return false
		}
	}
	return true
}

func Allowed(host string, p Policy, bindings []Resolved) bool {
	for _, pattern := range p.AllowHosts {
		if MatchHost(host, pattern) {
			return true
		}
	}
	for _, b := range bindings {
		for _, pattern := range b.Hosts {
			if MatchHost(host, pattern) {
				return true
			}
		}
	}
	return false
}

func validDNSHost(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) > 63 || !regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`).MatchString(label) {
			return false
		}
	}
	return true
}
