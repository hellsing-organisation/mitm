package certs

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateAndReload(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "ca.key")
	cert := filepath.Join(dir, "ca.crt")

	ca, err := LoadOrGenerateCA(key, cert, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(key); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cert); err != nil {
		t.Fatal(err)
	}

	ca2, err := LoadOrGenerateCA(key, cert, false)
	if err != nil {
		t.Fatal(err)
	}
	if !ca2.Certificate().Equal(ca.Certificate()) {
		t.Fatal("reload produced different cert")
	}
}

func TestLoadWithoutGenerateFailsOnMissing(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrGenerateCA(filepath.Join(dir, "k"), filepath.Join(dir, "c"), false); err == nil {
		t.Fatal("expected error for missing CA when generate=false")
	}
}

func TestGenerateCreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "deep", "er")
	if _, err := LoadOrGenerateCA(filepath.Join(nested, "ca.key"), filepath.Join(nested, "ca.crt"), true); err != nil {
		t.Fatalf("generate must create parent dirs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(nested, "ca.crt")); err != nil {
		t.Fatal(err)
	}
}

func TestLeafCacheAndIP(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(filepath.Join(dir, "k"), filepath.Join(dir, "c"), true)
	if err != nil {
		t.Fatal(err)
	}
	l1, err := ca.Leaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	l2, err := ca.Leaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(l1.Certificate) == 0 || len(l1.Certificate) != len(l2.Certificate) || l1.Certificate[0][0] != l2.Certificate[0][0] {
		t.Fatal("leaf not cached")
	}
	ipLeaf, err := ca.Leaf("10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ipLeaf.Certificate) == 0 {
		t.Fatal("empty ip leaf")
	}
}

func TestFullHandshakeWithMintedLeaf(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(filepath.Join(dir, "k"), filepath.Join(dir, "c"), true)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("example.com")
	if err != nil {
		t.Fatal(err)
	}

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	serverDone := make(chan error, 1)
	go func() {
		tlsConn := tls.Server(s, &tls.Config{
			Certificates: []tls.Certificate{leaf},
			MinVersion:   tls.VersionTLS12,
		})
		buf := make([]byte, 8)
		tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := tlsConn.Read(buf)
		serverDone <- err
		tlsConn.Close()
	}()

	clientErr := make(chan error, 1)
	go func() {
		tlsConn := tls.Client(c, &tls.Config{
			ServerName: "example.com",
			RootCAs:    ca.Pool(),
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsConn.Handshake(); err != nil {
			clientErr <- err
			return
		}
		_, err := tlsConn.Write([]byte("ping"))
		clientErr <- err
	}()

	if err := <-clientErr; err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server read: %v", err)
	}
}
