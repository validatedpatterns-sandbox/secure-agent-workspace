package rewrite

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/config"
)

var ErrRefresh = errors.New("credential refresh failed")

var ErrMarker = errors.New("unknown or unbound credential marker")

// Request replaces only markers bound to the TLS host. It never logs or
// returns a credential value, including in the error path.
func Request(r *http.Request, host, prefix string, bindings []config.Resolved) (string, error) {
	markerRE := regexp.MustCompile(regexp.QuoteMeta(prefix) + `\.[A-Za-z0-9._-]+`)
	used := map[string]bool{}
	replace := func(input string) (string, error) {
		bad := false
		var refreshErr error
		result := markerRE.ReplaceAllStringFunc(input, func(marker string) string {
			for _, b := range bindings {
				if b.Marker != marker {
					continue
				}
				for _, pattern := range b.Hosts {
					if config.MatchHost(host, pattern) {
						used[b.Secret] = true
						if b.Token != nil {
							value, err := b.Token(r.Context())
							if err != nil {
								refreshErr = ErrRefresh
								return marker
							}
							return value
						}
						return b.Value
					}
				}
			}
			bad = true
			return marker
		})
		if refreshErr != nil {
			return "", refreshErr
		}
		if bad || strings.Contains(result, prefix+".") {
			return "", ErrMarker
		}
		return result, nil
	}
	path, err := replace(r.URL.Path)
	if err != nil {
		return "", err
	}
	r.URL.Path, r.URL.RawPath = path, ""
	if r.URL.RawQuery != "" {
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return "", errors.New("invalid query")
		}
		for key, values := range query {
			newKey, err := replace(key)
			if err != nil {
				return "", err
			}
			for i, value := range values {
				values[i], err = replace(value)
				if err != nil {
					return "", err
				}
			}
			if newKey != key {
				delete(query, key)
				query[newKey] = append(query[newKey], values...)
			} else {
				query[key] = values
			}
		}
		r.URL.RawQuery = query.Encode()
	}
	for name, values := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "proxy-") {
			delete(r.Header, name)
			continue
		}
		for i, value := range values {
			if strings.EqualFold(name, "Authorization") && strings.HasPrefix(strings.ToLower(value), "basic ") {
				decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[6:]))
				if err != nil {
					return "", errors.New("invalid Basic authorization")
				}
				plain, err := replace(string(decoded))
				if err != nil {
					return "", err
				}
				values[i] = "Basic " + base64.StdEncoding.EncodeToString([]byte(plain))
				continue
			}
			values[i], err = replace(value)
			if err != nil {
				return "", err
			}
		}
	}
	names := make([]string, 0, len(used))
	for name := range used {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ","), nil
}
