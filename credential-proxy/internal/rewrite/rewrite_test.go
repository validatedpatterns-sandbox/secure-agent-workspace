package rewrite

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/config"
)

func TestRequestRewritesAllSupportedLocations(t *testing.T) {
	marker := "saw-cred.inference.api_key"
	r, _ := http.NewRequest("GET", "https://api.example.test/v1/"+marker+"?key="+marker, nil)
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:"+marker)))
	r.Header.Set("X-Api-Key", marker)
	r.Header.Set("Proxy-Authorization", "must-not-forward")
	b := []config.Resolved{{Marker: marker, Secret: "inference", Hosts: []string{"api.example.test"}, Value: "real-value"}}
	name, err := Request(r, "api.example.test", "saw-cred", b)
	if err != nil || name != "inference" {
		t.Fatalf("rewrite: %s %v", name, err)
	}
	if r.URL.Path != "/v1/real-value" || r.URL.Query().Get("key") != "real-value" || r.Header.Get("X-Api-Key") != "real-value" {
		t.Fatalf("path/query/header did not rewrite: %v %v", r.URL, r.Header)
	}
	decoded, err := base64.StdEncoding.DecodeString(r.Header.Get("Authorization")[6:])
	if err != nil || string(decoded) != "user:real-value" || r.Header.Get("Proxy-Authorization") != "" {
		t.Fatalf("Basic or proxy header: %q %v", decoded, err)
	}
}

func TestRequestRefusesUnknownAndUnboundMarkers(t *testing.T) {
	for _, tc := range []struct{ value, host string }{
		{"saw-cred.other.api_key", "api.example.test"},
		{"saw-cred.inference.api_key", "wrong.example.test"},
	} {
		r, _ := http.NewRequest("GET", "https://"+tc.host+"/v1", nil)
		r.Header.Set("X-Api-Key", tc.value)
		_, err := Request(r, tc.host, "saw-cred", []config.Resolved{{
			Marker: "saw-cred.inference.api_key", Secret: "inference",
			Hosts: []string{"api.example.test"}, Value: "real-value",
		}})
		if err != ErrMarker {
			t.Fatalf("%s: got %v", tc.value, err)
		}
	}
}
