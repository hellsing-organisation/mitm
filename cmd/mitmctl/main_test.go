package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hellsing-organization/mitm/internal/certs"
)

func TestCAGen(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "ca.key")
	cert := filepath.Join(dir, "ca.crt")

	if err := run([]string{"ca", "gen", "--key", key, "--cert", cert}); err != nil {
		t.Fatal(err)
	}
	if _, err := certs.LoadOrGenerateCA(key, cert, false); err != nil {
		t.Fatalf("generated CA not loadable: %v", err)
	}

	ca1, _ := certs.LoadOrGenerateCA(key, cert, false)
	if err := run([]string{"ca", "gen", "--key", key, "--cert", cert, "--force"}); err != nil {
		t.Fatal(err)
	}
	ca2, _ := certs.LoadOrGenerateCA(key, cert, false)
	if ca1.Certificate().SerialNumber.Cmp(ca2.Certificate().SerialNumber) == 0 {
		t.Fatal("--force must regenerate a different CA")
	}
}

func TestQueryFilters(t *testing.T) {
	dir := t.TempDir()
	events := `{"ts":"2026-10-18T01:00:00Z","type":"http","comm":"curl","sni":"a.example.com","http":{"method":"POST","host":"a.example.com","path":"/1","status":200}}
{"ts":"2026-10-18T01:00:01Z","type":"http","comm":"python","sni":"b.example.com","http":{"method":"GET","host":"b.example.com","path":"/2","status":404}}
{"ts":"2026-10-18T01:00:02Z","type":"flow","comm":"curl"}
`
	out := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(out, []byte(events), 0o644); err != nil {
		t.Fatal(err)
	}

	var sb strings.Builder
	queryPrint = func(s string) { sb.WriteString(s + "\n") }
	defer func() { queryPrint = nil }()

	if err := run([]string{"query", "--file", out, "--app", "curl"}); err != nil {
		t.Fatal(err)
	}
	got := sb.String()
	if !strings.Contains(got, "a.example.com") || strings.Contains(got, "b.example.com") {
		t.Fatalf("--app filter wrong:\n%s", got)
	}

	sb.Reset()
	if err := run([]string{"query", "--file", out, "--status", "404"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "b.example.com") || strings.Contains(sb.String(), "a.example.com") {
		t.Fatalf("--status filter wrong:\n%s", sb.String())
	}

	sb.Reset()
	if err := run([]string{"query", "--file", out, "--limit", "1"}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(sb.String(), "\n") != 1 {
		t.Fatalf("--limit wrong:\n%s", sb.String())
	}

	sb.Reset()
	if err := run([]string{"query", "--file", out, "--domain", "example.com"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "a.example.com") || !strings.Contains(sb.String(), "b.example.com") {
		t.Fatalf("--domain example.com should match both:\n%s", sb.String())
	}
}

func TestTailPrints(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(out, []byte(`{"ts":"2026-10-18T01:00:00Z","type":"alert","comm":"x","alert":{"kind":"unproxied_tls"}}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	tailPrint = func(s string) { sb.WriteString(s + "\n") }
	defer func() { tailPrint = nil }()
	if err := run([]string{"tail", "--file", out}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "unproxied_tls") {
		t.Fatalf("tail output wrong:\n%s", sb.String())
	}
}
