package redirect

import (
	"strings"
	"testing"

	"github.com/hellsing-organization/mitm/internal/config"
)

type fakeRunner struct {
	calls []call
}

type call struct {
	name string
	args []string
}

func (f *fakeRunner) Run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{name, args})
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

func TestNftOn(t *testing.T) {
	r := &fakeRunner{}
	m := NewNft(r, testCfg())
	if err := m.On(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.argv(), "\n")
	for _, want := range []string{
		"add table inet mitm_audit",
		"add rule inet mitm_audit output meta mark 1337 return",
		"add rule inet mitm_audit output tcp dport { 443, 8443 } redirect to :8080",
		"add rule inet mitm_audit outfilt udp dport 443 reject",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing rule %q in:\n%s", want, joined)
		}
	}
	if !strings.Contains(joined, "flush table inet mitm_audit") {
		t.Fatal("On must be idempotent (flush before add)")
	}
}

func TestNftOff(t *testing.T) {
	r := &fakeRunner{}
	m := NewNft(r, testCfg())
	if err := m.Off(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.argv(), "\n")
	if !strings.Contains(joined, "delete table inet mitm_audit") {
		t.Fatalf("Off must delete table, got:\n%s", joined)
	}
}

func TestIPTablesOnRoot(t *testing.T) {
	r := &fakeRunner{}
	m := NewIPTables(r, testCfg(), 0)
	if err := m.On(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.argv(), "\n")
	for _, want := range []string{
		"-t nat -N MITM_NAT_OUT",
		"-t nat -A OUTPUT -j MITM_NAT_OUT",
		"-t nat -A MITM_NAT_OUT -m mark --mark 1337 -j RETURN",
		"-t nat -A MITM_NAT_OUT -p tcp -m multiport --dports 443,8443 -j REDIRECT --to-ports 8080",
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
	for _, fam := range []string{"iptables", "ip6tables"} {
		if strings.Count(joined, fam) == 0 {
			t.Fatalf("%s never invoked:\n%s", fam, joined)
		}
	}
}

func TestIPTablesOnNonRoot(t *testing.T) {
	r := &fakeRunner{}
	m := NewIPTables(r, testCfg(), 1024)
	if err := m.On(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.argv(), "\n")
	if !strings.Contains(joined, "-m owner ! --uid-owner 1024 -j RETURN") {
		t.Fatalf("owner rule missing for uid 1024:\n%s", joined)
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
	joined := strings.Join(r.argv(), "\n")
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
	factory := Detect(lookPath)
	r := &fakeRunner{}
	m := factory(testCfg(), 1000)
	_ = m
	_ = r
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
	m := NewNft(r, testCfg())
	if _, err := m.Status(); err != nil {
		t.Fatal(err)
	}
	r2 := &fakeRunner{}
	m2 := NewIPTables(r2, testCfg(), 0)
	if _, err := m2.Status(); err != nil {
		t.Fatal(err)
	}
	if len(r2.calls) == 0 {
		t.Fatal("status must invoke commands")
	}
}
