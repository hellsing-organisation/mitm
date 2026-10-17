package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hellsing-organization/mitm/internal/audit"
	"github.com/hellsing-organization/mitm/internal/certs"
	"github.com/hellsing-organization/mitm/internal/config"
)

func writeTestConfig(t *testing.T, dir string) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Listen = "127.0.0.1:0"
	cfg.Redirect.Managed = false
	cfg.Output.Dir = dir
	cfg.CA = config.CAPaths{Key: filepath.Join(dir, "ca.key"), Cert: filepath.Join(dir, "ca.crt")}
	return cfg
}

func TestRunStartupAndShutdown(t *testing.T) {
	dir := t.TempDir()
	cfg := writeTestConfig(t, dir)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()

	waitForFile := func(p string) {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(p); err == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("file %s never appeared", p)
	}
	waitForFile(filepath.Join(dir, "ca.crt"))
	waitForFile(filepath.Join(dir, "events.jsonl"))

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not shut down")
	}
}

func TestRunServesTLS(t *testing.T) {
	dir := t.TempDir()
	cfg := writeTestConfig(t, dir)
	cfg.Listen = "127.0.0.1:0"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go run(ctx, cfg)

	var caPath string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(filepath.Join(dir, "ca.crt")); err == nil {
			caPath = string(b)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if caPath == "" {
		t.Fatal("CA never generated")
	}
	ca, err := certs.LoadOrGenerateCA(cfg.CA.Key, cfg.CA.Cert, false)
	if err != nil {
		t.Fatal(err)
	}

	var addr string
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(filepath.Join(dir, "proxy.addr"))
		if err == nil {
			addr = strings.TrimSpace(string(b))
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("proxy addr never written")
	}

	tc, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName: "example.com",
		RootCAs:    ca.Pool(),
		NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("TLS dial to proxy: %v", err)
	}
	tc.Close()
	cancel()

	data, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var foundStartup bool
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad event line: %v", err)
		}
		if e.Type == audit.TypeStartup {
			foundStartup = true
		}
	}
	if !foundStartup {
		t.Fatal("no startup event")
	}
	_ = http.Client{}
	_ = net.IPv4len
}
