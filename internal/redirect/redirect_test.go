package redirect

import (
	"errors"
	"strings"
	"testing"

	"github.com/hellsing-organization/mitm/internal/config"
)

type fakeRunner struct {
	calls  []call
	failOn []string
}

type call struct {
	name string
	args []string
}

func (f *fakeRunner) Run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{name, args})
	joined := name + " " + strings.Join(args, " ")
	for _, sub := range f.failOn {
		if strings.Contains(joined, sub) {
			return []byte("boom"), errors.New("boom")
		}
	}
	return nil, nil
}

func (f *fakeRunner) argv() []string {
	out := []string{}
	for _, c := range f.calls {
		out = append(out, c.name+" "+strings.Join(c.args, " "))
	}
	return out
}

func testCfg() config.Config {
	cfg := config.Default()
	cfg.Listen = "127.0.0.1:8080"
	cfg.Ports = []int{443, 8443}
	cfg.QUIC.ForceTCP = true
	return cfg
}

func assertOneCommandPerCall(t *testing.T, r *fakeRunner, cmd string) {
	t.Helper()
	for _, c := range r.calls {
		if c.name != cmd {
			continue
		}
		n := 0
		for _, marker := range []string{"add table", "flush table", "delete table", "add chain", "add rule"} {
			n += strings.Count(strings.Join(c.args, " "), marker)
		}
		if n > 1 {
			t.Fatalf("one invocation must carry one command, got %d in %v", n, c.args)
		}
	}
}

func TestNftOneCommandPerInvocation(t *testing.T) {
	r := &fakeRunner{}
	if err := NewNft(r, testCfg()).On(); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) < 6 {
		t.Fatalf("expected one call per command, got %d: %v", len(r.calls), r.argv())
	}
	assertOneCommandPerCall(t, r, "nft")

	joined := strings.Join(r.argv(), "\n")
	for _, want := range []string{
		"nft delete table inet mitm_audit",
		"nft add table inet mitm_audit",
		"nft add chain inet mitm_audit output { type nat hook output priority -100 ; policy accept ; }",
		"nft add rule inet mitm_audit output meta mark 1337 return",
		"nft add rule inet mitm_audit output tcp dport { 443, 8443 } redirect to :8080",
		"nft add chain inet mitm_audit outfilt { type filter hook output priority 0 ; policy accept ; }",
		"nft add rule inet mitm_audit outfilt udp dport 443 reject",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
}

func TestNftToleratesAbsentTable(t *testing.T) {
	r := &fakeRunner{failOn: []string{"delete table"}}
	if err := NewNft(r, testCfg()).On(); err != nil {
		t.Fatalf("delete of absent table must be tolerated: %v", err)
	}
	r2 := &fakeRunner{failOn: []string{"add rule"}}
	if err := NewNft(r2, testCfg()).On(); err == nil {
		t.Fatal("real add failures must surface")
	}
}

func TestNftOff(t *testing.T) {
	r := &fakeRunner{}
	if err := NewNft(r, testCfg()).Off(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.argv(), "\n")
	if !strings.Contains(joined, "nft delete table inet mitm_audit") {
		t.Fatalf("Off must delete table, got:\n%s", joined)
	}
}

func iptCmds(r *fakeRunner) []string {
	var out []string
	for _, c := range r.calls {
		if c.name == "iptables" || c.name == "ip6tables" {
			out = append(out, strings.Join(c.args, " "))
		}
	}
	return out
}

func TestIPTablesOneCommandPerInvocation(t *testing.T) {
	r := &fakeRunner{}
	if err := NewIPTables(r, testCfg(), 0).On(); err != nil {
		t.Fatal(err)
	}
	for _, args := range iptCmds(r) {
		n := 0
		for _, marker := range []string{" -N ", " -A ", " -F ", " -D ", " -X "} {
			n += strings.Count(" "+args+" ", marker)
		}
		if n > 1 {
			t.Fatalf("one invocation must carry one iptables command, got %d in %q", n, args)
		}
	}
	joined := strings.Join(iptCmds(r), "\n")
	for _, want := range []string{
		"-t nat -D OUTPUT -j MITM_NAT_OUT",
		"-t nat -X MITM_NAT_OUT",
		"-t nat -N MITM_NAT_OUT",
		"-t nat -A OUTPUT -j MITM_NAT_OUT",
		"-t nat -A MITM_NAT_OUT -m mark --mark 1337 -j RETURN",
		"-t nat -A MITM_NAT_OUT -p tcp -m multiport --dports 443,8443 -j REDIRECT --to-ports 8080",
		"-D OUTPUT -j MITM_FILT_OUT",
		"-N MITM_FILT_OUT",
		"-A OUTPUT -j MITM_FILT_OUT",
		"-A MITM_FILT_OUT -p udp -m multiport --dports 443 -j REJECT",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "--uid-owner") {
		t.Fatal("uid 0 must not add owner rule")
	}
}

func TestIPTablesNonRootOwnerRule(t *testing.T) {
	r := &fakeRunner{}
	if err := NewIPTables(r, testCfg(), 1024).On(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(iptCmds(r), "\n")
	if !strings.Contains(joined, "-t nat -A MITM_NAT_OUT -m owner ! --uid-owner 1024 -j RETURN") {
		t.Fatalf("owner rule missing:\n%s", joined)
	}
}

func TestIPTablesToleratesStaleState(t *testing.T) {
	r := &fakeRunner{failOn: []string{"-D OUTPUT", "-X MITM"}}
	if err := NewIPTables(r, testCfg(), 0).On(); err != nil {
		t.Fatalf("stale-state cleanup failures must be tolerated: %v", err)
	}
	r2 := &fakeRunner{failOn: []string{"REDIRECT"}}
	if err := NewIPTables(r2, testCfg(), 0).On(); err == nil {
		t.Fatal("real add failures must surface")
	}
}

func TestIPTablesOff(t *testing.T) {
	r := &fakeRunner{}
	m := NewIPTables(r, testCfg(), 1000)
	if err := m.On(); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	if err := m.Off(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(iptCmds(r), "\n")
	for _, want := range []string{
		"-t nat -D OUTPUT -j MITM_NAT_OUT",
		"-t nat -F MITM_NAT_OUT",
		"-t nat -X MITM_NAT_OUT",
		"-D OUTPUT -j MITM_FILT_OUT",
		"-F MITM_FILT_OUT",
		"-X MITM_FILT_OUT",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
}

func TestDetectPrefersNft(t *testing.T) {
	lookPath := func(name string) string {
		if name == "nft" {
			return "/usr/sbin/nft"
		}
		return ""
	}
	m := Detect(lookPath)(testCfg(), 1000)
	switch m.(type) {
	case *NftManager:
	default:
		t.Fatalf("want NftManager, got %T", m)
	}

	lookPath2 := func(name string) string {
		if name == "iptables" {
			return "/usr/sbin/iptables"
		}
		return ""
	}
	m2 := Detect(lookPath2)(testCfg(), 0)
	switch m2.(type) {
	case *IPTablesManager:
	default:
		t.Fatalf("want IPTablesManager, got %T", m2)
	}
}

func TestStatusCommands(t *testing.T) {
	r := &fakeRunner{}
	if _, err := NewNft(r, testCfg()).Status(); err != nil {
		t.Fatal(err)
	}
	r2 := &fakeRunner{}
	if _, err := NewIPTables(r2, testCfg(), 0).Status(); err != nil {
		t.Fatal(err)
	}
	if len(r2.calls) == 0 {
		t.Fatal("status must invoke commands")
	}
}
