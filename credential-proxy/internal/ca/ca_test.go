package ca

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"testing"
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
