package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDefault(t *testing.T) {
	c := Default()
	if c.Listen != "127.0.0.1:8080" {
		t.Fatalf("listen = %q", c.Listen)
	}
	if len(c.Ports) != 1 || c.Ports[0] != 443 {
		t.Fatalf("ports = %v", c.Ports)
	}
	if c.Redirect.Mark != 1337 {
		t.Fatalf("mark = %d", c.Redirect.Mark)
	}
	if !c.QUIC.ForceTCP {
		t.Fatal("force_tcp default false")
	}
	if c.Capture.MaxBodyBytes != 16777216 {
		t.Fatalf("max body = %d", c.Capture.MaxBodyBytes)
	}
	if c.Output.Dir != "/var/log/mitm-audit" || c.Output.JSONL != "events.jsonl" {
		t.Fatalf("output = %+v", c.Output)
	}
	if !c.Capture.Bodies {
		t.Fatal("bodies default false")
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != Default().Listen {
		t.Fatalf("listen = %q", c.Listen)
	}
}

func TestLoadPartialOverride(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	err := os.WriteFile(p, []byte("listen: 127.0.0.1:9999\nports: [443, 8443]\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:9999" {
		t.Fatalf("listen = %q", c.Listen)
	}
	if len(c.Ports) != 2 || c.Ports[0] != 443 || c.Ports[1] != 8443 {
		t.Fatalf("ports = %v", c.Ports)
	}
	if c.Capture.MaxBodyBytes != Default().Capture.MaxBodyBytes {
		t.Fatal("defaults not retained for unset fields")
	}
}

func TestValidateRejects(t *testing.T) {
	bad := []Config{
		{Listen: "nope"},
		func() Config { c := Default(); c.Ports = nil; return c }(),
		func() Config { c := Default(); c.Ports = []int{0}; return c }(),
		func() Config { c := Default(); c.Ports = []int{70000}; return c }(),
		func() Config { c := Default(); c.Redirect.Mark = 0; return c }(),
		func() Config { c := Default(); c.Capture.MaxBodyBytes = 0; return c }(),
		func() Config { c := Default(); c.Output.Dir = ""; return c }(),
		func() Config { c := Default(); c.CA.Key = ""; return c }(),
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	if err := Default().Validate(); err != nil {
		t.Fatalf("default rejected: %v", err)
	}
}

func TestMatchDomain(t *testing.T) {
	c := Default()
	if !c.MatchDomain("api.example.com") {
		t.Fatal("empty include should match all")
	}
	c.Filters.IncludeDomains = []string{"*.example.com"}
	if c.MatchDomain("api.other.org") {
		t.Fatal("include should not match other.org")
	}
	if !c.MatchDomain("api.example.com") {
		t.Fatal("include glob failed")
	}
	c.Filters.ExcludeDomains = []string{"ads.example.com"}
	if c.MatchDomain("ads.example.com") {
		t.Fatal("exclude must win")
	}
	if !c.MatchDomain("api.example.com:443") {
		t.Fatal("port must be stripped")
	}
}

func TestMatchComm(t *testing.T) {
	c := Default()
	if !c.MatchComm("curl") {
		t.Fatal("curl should match")
	}
	if c.MatchComm("mitmd") {
		t.Fatal("mitmd must be excluded by default")
	}
}

func TestMatchContentType(t *testing.T) {
	c := Default()
	if !c.MatchContentType("application/json; charset=utf-8") {
		t.Fatal("params must be stripped before match")
	}
	if c.MatchContentType("image/png") {
		t.Fatal("image/* excluded by default")
	}
	if !c.MatchContentType("application/octet-stream") {
		t.Fatal("*/* must match everything not excluded")
	}
}

func TestLoadExampleYAML(t *testing.T) {
	c, err := Load("../../configs/mitm.example.yaml")
	if err != nil {
		t.Fatalf("example config invalid: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("example config fails validation: %v", err)
	}
}

func TestRoundTripYAML(t *testing.T) {
	c := Default()
	b, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var c2 Config
	if err := yaml.Unmarshal(b, &c2); err != nil {
		t.Fatal(err)
	}
	if c2.Listen != c.Listen || c2.Redirect.Mark != c.Redirect.Mark {
		t.Fatalf("round trip mismatch: %+v", c2)
	}
}
