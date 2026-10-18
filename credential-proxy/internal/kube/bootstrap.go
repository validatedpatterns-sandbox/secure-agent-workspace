package kube

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/ca"
)

type client struct {
	base, token string
	http        *http.Client
}

type object struct {
	APIVersion string            `json:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty"`
	Metadata   metadata          `json:"metadata"`
	Type       string            `json:"type,omitempty"`
	Data       map[string]string `json:"data,omitempty"`
}

type metadata struct {
	Name            string `json:"name"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
}

func newClient() (*client, error) {
	const sa = "/var/run/secrets/kubernetes.io/serviceaccount"
	token, err := os.ReadFile(filepath.Join(sa, "token"))
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(sa, "ca.crt"))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid Kubernetes API CA")
	}
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("Kubernetes API service is not configured")
	}
	return &client{
		base:  "https://" + host + ":" + port,
		token: strings.TrimSpace(string(token)),
		http: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
			Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		}},
	}, nil
}

func (c *client) call(method, path string, body *object) (int, object, error) {
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, object{}, err
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.base+path, payload)
	if err != nil {
		return 0, object{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, object{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, object{}, nil
	}
	var result object
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&result); err != nil {
		return 0, object{}, err
	}
	return resp.StatusCode, result, nil
}

// InitCA creates the private CA exactly once. A second hook run only repairs
// the public ConfigMap; it never replaces an existing signing key.
func InitCA(namespace, secretName, mapName string) error {
	if namespace == "" || secretName == "" || mapName == "" {
		return errors.New("namespace and CA object names are required")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	return initCA(c, namespace, secretName, mapName)
}

func initCA(c *client, namespace, secretName, mapName string) error {
	base := "/api/v1/namespaces/" + namespace
	secretPath := base + "/secrets/" + secretName
	status, secret, err := c.call(http.MethodGet, secretPath, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		cert, key, err := ca.Generate()
		if err != nil {
			return err
		}
		created := object{APIVersion: "v1", Kind: "Secret", Metadata: metadata{Name: secretName}, Type: "Opaque",
			Data: map[string]string{"tls.crt": base64.StdEncoding.EncodeToString(cert),
				"tls.key": base64.StdEncoding.EncodeToString(key)}}
		status, secret, err = c.call(http.MethodPost, base+"/secrets", &created)
		if err != nil {
			return err
		}
		if status == http.StatusConflict {
			status, secret, err = c.call(http.MethodGet, secretPath, nil)
			if err != nil {
				return err
			}
		}
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("read or create proxy CA Secret: HTTP %d", status)
	}
	certPEM, err := base64.StdEncoding.DecodeString(secret.Data["tls.crt"])
	if err != nil {
		return errors.New("proxy CA Secret has invalid certificate data")
	}
	keyPEM, err := base64.StdEncoding.DecodeString(secret.Data["tls.key"])
	if err != nil {
		return errors.New("proxy CA Secret has invalid key data")
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return errors.New("proxy CA Secret has an invalid certificate/key pair")
	}
	mapPath := base + "/configmaps/" + mapName
	status, existing, err := c.call(http.MethodGet, mapPath, nil)
	if err != nil {
		return err
	}
	if status == http.StatusOK && existing.Data["ca.crt"] == string(certPEM) {
		return nil
	}
	configMap := object{APIVersion: "v1", Kind: "ConfigMap", Metadata: metadata{Name: mapName},
		Data: map[string]string{"ca.crt": string(certPEM)}}
	method, path := http.MethodPost, base+"/configmaps"
	if status == http.StatusOK {
		method, path = http.MethodPut, mapPath
		configMap.Metadata.ResourceVersion = existing.Metadata.ResourceVersion
	} else if status != http.StatusNotFound {
		return fmt.Errorf("read proxy CA ConfigMap: HTTP %d", status)
	}
	status, _, err = c.call(method, path, &configMap)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("write proxy CA ConfigMap: HTTP %d", status)
	}
	return nil
}
