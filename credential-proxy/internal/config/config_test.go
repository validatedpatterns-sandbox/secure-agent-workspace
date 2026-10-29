package config

import (
	"encoding/json"
	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/oauth"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSharedSecretUsesAllowedTypesAndExplicitProviderNarrowsHosts(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secrets", "inference")
	if err := os.MkdirAll(secret, 0700); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(root, "config.json")
	if err := os.WriteFile(policy, []byte(`{"markerPrefix":"saw-cred","allowHosts":["api.example.test","other.example.test","custom.example.test"],"profiles":{"nvidia":["api.example.test"],"build":["api.example.test"],"openai":["other.example.test"]},"bindings":[{"secret":"inference","key":"api_key","providers":["nvidia","build","openai","custom-inference"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"api_key": "test-key", "url": "https://custom.example.test/v1"} {
		if err := os.WriteFile(filepath.Join(secret, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := New(policy, filepath.Join(root, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		provider string
		hosts    []string
	}{
		{"", []string{"api.example.test", "other.example.test", "custom.example.test"}},
		{"nvidia", []string{"api.example.test", "custom.example.test"}},
		{"custom-inference", []string{"custom.example.test"}},
	} {
		if err := os.WriteFile(filepath.Join(secret, "provider"), []byte(tc.provider), 0600); err != nil {
			t.Fatal(err)
		}
		_, bindings, err := store.Snapshot()
		if err != nil || len(bindings) != 1 {
			t.Fatalf("provider %q: %v", tc.provider, err)
		}
		if !reflect.DeepEqual(bindings[0].Hosts, tc.hosts) {
			t.Fatalf("provider %q: hosts %v, want %v", tc.provider, bindings[0].Hosts, tc.hosts)
		}
	}
	if err := os.WriteFile(filepath.Join(secret, "provider"), []byte("unbound"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Snapshot(); err == nil {
		t.Fatal("an explicit unbound provider must be refused")
	}
}

func TestSnapshotFollowsSecretRotation(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secrets", "inference")
	if err := os.MkdirAll(secret, 0700); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(root, "config.json")
	if err := os.WriteFile(policy, []byte(`{"markerPrefix":"saw-cred","allowHosts":["api.example.test"],"profiles":{"nvidia":["api.example.test"]},"bindings":[{"secret":"inference","key":"api_key","providers":["nvidia"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"provider": "nvidia", "api_key": "first-key"} {
		if err := os.WriteFile(filepath.Join(secret, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := New(policy, filepath.Join(root, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	_, bindings, err := store.Snapshot()
	if err != nil || bindings[0].Value != "first-key" {
		t.Fatalf("first snapshot: %v %v", bindings, err)
	}
	if err := os.WriteFile(filepath.Join(secret, "api_key"), []byte("rotated-key"), 0600); err != nil {
		t.Fatal(err)
	}
	_, bindings, err = store.Snapshot()
	if err != nil || bindings[0].Value != "rotated-key" {
		t.Fatalf("rotated snapshot: %v %v", bindings, err)
	}
	if err := os.WriteFile(filepath.Join(secret, "url"), []byte("http://private.example.test:8000/v1"), 0600); err != nil {
		t.Fatal(err)
	}
	_, bindings, err = store.Snapshot()
	if err != nil || len(bindings[0].Hosts) != 1 || bindings[0].Hosts[0] != "api.example.test" {
		t.Fatalf("plain HTTP URL must not become an intercept binding: %v %v", bindings, err)
	}
	if err := os.WriteFile(filepath.Join(secret, "url"), []byte("https://custom.example.test/v1"), 0600); err != nil {
		t.Fatal(err)
	}
	_, bindings, err = store.Snapshot()
	if err != nil || len(bindings[0].Hosts) != 2 || bindings[0].Hosts[1] != "custom.example.test" {
		t.Fatalf("custom HTTPS host was not bound: %v %v", bindings, err)
	}
	if err := os.Remove(filepath.Join(secret, "api_key")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Snapshot(); err == nil {
		t.Fatal("missing key must make the proxy unready")
	}
}

func TestKeylessHTTPDoesNotRequireAnInterceptBinding(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secrets", "inference")
	if err := os.MkdirAll(secret, 0700); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(root, "config.json")
	if err := os.WriteFile(policy, []byte(`{"markerPrefix":"saw-cred","allowHosts":["api.example.test"],"profiles":{},"bindings":[{"secret":"inference","key":"api_key","providers":["custom-inference"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := New(policy, filepath.Join(root, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"", "unused-key"} {
		if err := os.WriteFile(filepath.Join(secret, "api_key"), []byte(key), 0600); err != nil {
			t.Fatal(err)
		}
		for _, endpoint := range []string{"http://models.example.test:8000/v1", "https://models.example.test/v1"} {
			if err := os.WriteFile(filepath.Join(secret, "url"), []byte(endpoint), 0600); err != nil {
				t.Fatal(err)
			}
			_, bindings, err := store.Snapshot()
			if endpoint[:5] == "http:" {
				if err != nil || len(bindings) != 0 {
					t.Fatalf("HTTP must stay ready without intercepting: %v %v", bindings, err)
				}
			} else if key == "" && err == nil {
				t.Fatal("HTTPS still requires its bound key")
			} else if key != "" && (err != nil || len(bindings) != 1) {
				t.Fatalf("HTTPS must still bind its key: %v %v", bindings, err)
			}
		}
	}
}

func TestWildcardIsOneLabel(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"us-aiplatform.googleapis.com", true},
		{"us.east-aiplatform.googleapis.com", false},
		{"else.googleapis.com", false},
	} {
		if got := MatchHost(tc.host, "*-aiplatform.googleapis.com"); got != tc.want {
			t.Fatalf("%s: got %t, want %t", tc.host, got, tc.want)
		}
	}
}

func TestRefreshBindingValidationAndMetadataOnlySnapshot(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "gmail")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"client_id", "client_secret", "refresh_token"} {
		if err := os.WriteFile(filepath.Join(dir, key), []byte("present"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	spec := &Refresh{Strategy: "oauth2_refresh_token", TokenURL: "https://oauth2.googleapis.com/token", RefreshBeforeSeconds: 300, MaxLifetimeSeconds: 3600, Material: oauth.Material{ClientID: "client_id", ClientSecret: "client_secret", RefreshToken: "refresh_token"}}
	policy := Policy{MarkerPrefix: "saw-cred", AllowHosts: []string{"oauth2.googleapis.com"}, Profiles: map[string][]string{"gmail": {"gmail.googleapis.com"}}, Bindings: []Binding{{Secret: "gmail", Key: "access_token", Providers: []string{"gmail"}, Refresh: spec}}}
	path := filepath.Join(root, "config.json")
	save := func() {
		raw, _ := json.Marshal(policy)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	save()
	store, err := New(path, root)
	if err != nil {
		t.Fatal(err)
	}
	_, bindings, err := store.Snapshot()
	if err != nil || len(bindings) != 1 || bindings[0].Value != "" || bindings[0].Token == nil {
		t.Fatal("refresh snapshot must need no access_token file or HTTP request")
	}
	for _, key := range []string{"client_id", "client_secret", "refresh_token"} {
		if err := os.Remove(filepath.Join(dir, key)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.Snapshot(); err == nil {
			t.Fatal("missing refresh material accepted")
		}
		if err := os.WriteFile(filepath.Join(dir, key), []byte("present"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []string{"http://oauth2.googleapis.com/token", "https://oauth2.googleapis.com:8443/token", "https://user@oauth2.googleapis.com/token", "https://oauth2.googleapis.com/token?x=y", "https://oauth2.googleapis.com/token#fragment", "https://else.example.test/token", "https://oauth2..googleapis.com/token"} {
		spec.TokenURL = bad
		save()
		if _, err := New(path, root); err == nil {
			t.Errorf("accepted invalid tokenURL %s", bad)
		}
	}
	spec.TokenURL = "https://oauth2.googleapis.com/token"
	for _, key := range []string{"../client_id", "..", "bad/key", ""} {
		spec.Material.ClientID = key
		save()
		if _, err := New(path, root); err == nil {
			t.Error("accepted invalid material key")
		}
	}
	spec.Material.ClientID = "client_id"
	for _, limits := range [][2]int{{-1, 3600}, {3600, 3600}, {0, 86401}, {0, 0}} {
		spec.RefreshBeforeSeconds, spec.MaxLifetimeSeconds = limits[0], limits[1]
		save()
		if _, err := New(path, root); err == nil {
			t.Error("accepted invalid refresh lifetime")
		}
	}
}
