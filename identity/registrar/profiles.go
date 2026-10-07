package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"gopkg.in/yaml.v3"
)

var dnsName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

type profileDoc struct {
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Enabled   *bool `yaml:"enabled"`
		Sandboxes []struct {
			Name    string `yaml:"name"`
			Enabled *bool  `yaml:"enabled"`
		} `yaml:"sandboxes"`
	} `yaml:"spec"`
}

func enabled(b *bool) bool               { return b == nil || *b }
func id(td, path string) *types.SPIFFEID { return &types.SPIFFEID{TrustDomain: td, Path: path} }

// desiredEntries deliberately reads only BOM workspaces/sandboxes, never labels
// supplied by a workload or an arbitrary SPIFFE ID supplied by a tenant.
func desiredEntries(td, ns, vm, uid, parent string, files map[string]string, gatewayUID string, jwtSvid, x509Svid int32) ([]*types.Entry, error) {
	base := "/saw/" + ns + "/" + vm
	entry := func(path string, selectors ...*types.Selector) *types.Entry {
		return &types.Entry{SpiffeId: id(td, path), ParentId: id(td, parent), Selectors: selectors,
			JwtSvidTtl: jwtSvid, X509SvidTtl: x509Svid, Hint: "saw:" + uid}
	}
	out := []*types.Entry{entry(base+"/gateway",
		&types.Selector{Type: "unix", Value: "uid:" + gatewayUID},
		&types.Selector{Type: "unix", Value: "path:/usr/local/bin/openshell-gateway"})}
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	seen := map[string]bool{}
	for _, key := range keys {
		parts := strings.Split(key, "__")
		if len(parts) != 4 || parts[0] != "profiles" || parts[3] != "workspace.yaml" {
			continue
		}
		var ws profileDoc
		if err := yaml.Unmarshal([]byte(files[key]), &ws); err != nil {
			return nil, fmt.Errorf("invalid workspace document")
		}
		if !enabled(ws.Spec.Enabled) {
			continue
		}
		name := ws.Metadata.Name
		if name == "" {
			name = parts[2]
		}
		if !dnsName.MatchString(name) || len(name) > 19 || seen[name] {
			return nil, fmt.Errorf("invalid or duplicate workspace %q", name)
		}
		seen[name] = true
		parts[3] = "sandbox.yaml"
		raw := files[strings.Join(parts, "__")]
		if raw == "" {
			continue
		}
		var sandboxes profileDoc
		if err := yaml.Unmarshal([]byte(raw), &sandboxes); err != nil {
			return nil, fmt.Errorf("invalid sandbox document")
		}
		sbSeen := map[string]bool{}
		for _, sb := range sandboxes.Spec.Sandboxes {
			if !enabled(sb.Enabled) {
				continue
			}
			if !dnsName.MatchString(sb.Name) || len(sb.Name) > 19 || sbSeen[sb.Name] {
				return nil, fmt.Errorf("invalid or duplicate sandbox %q", sb.Name)
			}
			sbSeen[sb.Name] = true
			out = append(out, entry(base+"/ws/"+name+"/sandbox/"+sb.Name,
				&types.Selector{Type: "docker", Value: "label:openshell.managed:true"},
				&types.Selector{Type: "docker", Value: "label:openshell.ai/sandbox-workspace:" + name},
				&types.Selector{Type: "docker", Value: "label:openshell.ai/sandbox-name:" + sb.Name}))
		}
	}
	return out, nil
}
