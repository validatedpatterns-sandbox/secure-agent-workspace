package kube

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInitCAIsIdempotent(t *testing.T) {
	var secret, configMap object
	secretPosts, configPosts := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/namespaces/saw-test/secrets/saw-credential-proxy-ca":
			if secret.Metadata.Name == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(secret)
		case "/api/v1/namespaces/saw-test/secrets":
			secretPosts++
			_ = json.NewDecoder(r.Body).Decode(&secret)
			_ = json.NewEncoder(w).Encode(secret)
		case "/api/v1/namespaces/saw-test/configmaps/saw-proxy-ca":
			if configMap.Metadata.Name == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(configMap)
		case "/api/v1/namespaces/saw-test/configmaps":
			configPosts++
			_ = json.NewDecoder(r.Body).Decode(&configMap)
			_ = json.NewEncoder(w).Encode(configMap)
		default:
			t.Errorf("unexpected API request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	c := &client{base: server.URL, token: "test-token", http: server.Client()}
	for range 2 {
		if err := initCA(c, "saw-test", "saw-credential-proxy-ca", "saw-proxy-ca"); err != nil {
			t.Fatal(err)
		}
	}
	if secretPosts != 1 || configPosts != 1 || secret.Data["tls.key"] == "" || configMap.Data["ca.crt"] == "" {
		t.Fatalf("CA recreated or incomplete: secret POSTs=%d, ConfigMap POSTs=%d", secretPosts, configPosts)
	}
}
