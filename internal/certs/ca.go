package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type CA struct {
	cert    *x509.Certificate
	certDER []byte
	key     crypto.Signer
	pool    *x509.CertPool

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
	order []string
}

const leafCacheMax = 4096

func LoadOrGenerateCA(keyPath, certPath string, generate bool) (*CA, error) {
	keyPEM, keyErr := os.ReadFile(keyPath)
	certPEM, certErr := os.ReadFile(certPath)
	if keyErr == nil && certErr == nil {
		return parseCA(keyPEM, certPEM)
	}
	if !generate {
		return nil, fmt.Errorf("ca files missing (%v, %v) and generate=false", keyErr, certErr)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mitm-audit"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caKey.Public(), caKey)
	if err != nil {
		return nil, err
	}

	keyBytes, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	return parseCA(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func parseCA(keyPEM, certPEM []byte) (*CA, error) {
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("bad ca key pem")
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("bad ca cert pem")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	var key crypto.Signer
	if k, err := x509.ParseECPrivateKey(kb.Bytes); err == nil {
		key = k
	} else {
		krsa, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ca key: %w", err)
		}
		key = krsa
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, fmt.Errorf("ca cert not self-signed: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{
		cert:    cert,
		certDER: cb.Bytes,
		key:     key,
		pool:    pool,
		leafs:   make(map[string]*tls.Certificate),
	}, nil
}

func (c *CA) Certificate() *x509.Certificate { return c.cert }

func (c *CA) Pool() *x509.CertPool { return c.pool }

func (c *CA) Leaf(host string) (tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if leaf, ok := c.leafs[host]; ok {
		c.touchLocked(host)
		return *leaf, nil
	}
	leaf, err := c.mintLocked(host)
	if err != nil {
		return tls.Certificate{}, err
	}
	c.leafs[host] = leaf
	c.order = append(c.order, host)
	if len(c.order) > leafCacheMax {
		evict := c.order[0]
		c.order = c.order[1:]
		delete(c.leafs, evict)
	}
	return *leaf, nil
}

func (c *CA) TLSCert(host string) (*tls.Certificate, error) {
	leaf, err := c.Leaf(host)
	if err != nil {
		return nil, err
	}
	return &leaf, nil
}

func (c *CA) touchLocked(host string) {
	for i, h := range c.order {
		if h == host {
			c.order = append(c.order[:i], c.order[i+1:]...)
			c.order = append(c.order, host)
			return
		}
	}
}

func (c *CA) mintLocked(host string) (*tls.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, leafKey.Public(), c.key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.certDER},
		PrivateKey:  leafKey,
	}, nil
}

func randSerial() (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
