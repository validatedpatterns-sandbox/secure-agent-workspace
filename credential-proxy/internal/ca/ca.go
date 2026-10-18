package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

type Authority struct {
	certPath, keyPath string
	mu                sync.Mutex
	digest            [32]byte
	cert              *x509.Certificate
	key               crypto.Signer
	cache             map[string]tls.Certificate
}

func New(certPath, keyPath string) *Authority {
	return &Authority{certPath: certPath, keyPath: keyPath, cache: map[string]tls.Certificate{}}
}

func (a *Authority) Ready() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reload()
}

func (a *Authority) reload() error {
	certPEM, err := os.ReadFile(a.certPath)
	if err != nil {
		return fmt.Errorf("read proxy CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(a.keyPath)
	if err != nil {
		return fmt.Errorf("read proxy CA key: %w", err)
	}
	digest := sha256.Sum256(append(append([]byte(nil), certPEM...), keyPEM...))
	if digest == a.digest && a.cert != nil {
		return nil
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("invalid proxy CA pair: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || !cert.IsCA || time.Now().After(cert.NotAfter) {
		return errors.New("proxy CA certificate is invalid or expired")
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("proxy CA key cannot sign")
	}
	a.cert, a.key, a.digest = cert, signer, digest
	a.cache = map[string]tls.Certificate{}
	return nil
}

func (a *Authority) Certificate(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.reload(); err != nil {
		return nil, err
	}
	if cert, ok := a.cache[host]; ok && cert.Leaf != nil && time.Until(cert.Leaf.NotAfter) > time.Hour {
		return &cert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	expires := now.Add(24 * time.Hour)
	if a.cert.NotAfter.Before(expires) {
		expires = a.cert.NotAfter
	}
	leaf := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: expires,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	result := tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: key, Leaf: leaf}
	a.cache[host] = result
	return &result, nil
}

func Generate() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	keyID := make([]byte, 20)
	if _, err := rand.Read(keyID); err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"SAW"}, CommonName: "saw-credential-proxy-ca"},
		NotBefore:    now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: keyID, AuthorityKeyId: keyID,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	priv, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv}), nil
}
