package ca

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGeneratedCAHasMatchingKeyIdentifiers(t *testing.T) {
	certPEM, _, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("CA certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.SubjectKeyId) == 0 || !bytes.Equal(cert.SubjectKeyId, cert.AuthorityKeyId) {
		t.Fatal("self-signed CA needs matching subject and authority key IDs")
	}
}

func TestCAIsShortLivedAndConstrained(t *testing.T) {
	certPEM, keyPEM, err := Generate("api.example.test", "*.provider.example.test")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.NotAfter.Sub(cert.NotBefore) > 367*24*time.Hour || !cert.MaxPathLenZero || !cert.PermittedDNSDomainsCritical {
		t.Fatal("CA validity or constraints are missing")
	}
	root := t.TempDir()
	crt, key := filepath.Join(root, "ca.crt"), filepath.Join(root, "ca.key")
	if err := os.WriteFile(crt, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	a := New(crt, key)
	for _, host := range []string{"api.example.test", "one.provider.example.test"} {
		if _, err := a.Certificate(host); err != nil {
			t.Fatal("permitted certificate refused")
		}
	}
	if _, err := a.Certificate("attacker.example.test"); err == nil {
		t.Fatal("unrelated host certificate accepted")
	}
}
