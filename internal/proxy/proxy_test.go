package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
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

type upstream struct {
	ca     *certs.CA
	srv    *http.Server
	ln     net.Listener
	gotReq chan upstreamReq
}

type upstreamReq struct {
	Method string
	Path   string
	Host   string
	Body   string
	Header string
}

func startUpstream(t *testing.T) *upstream {
	t.Helper()
	dir := t.TempDir()
	ca, err := certs.LoadOrGenerateCA(filepath.Join(dir, "k"), filepath.Join(dir, "c"), true)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan upstreamReq, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/echo", func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 4096)
		n, _ := r.Body.Read(b)
		select {
		case got <- upstreamReq{Method: r.Method, Path: r.URL.RequestURI(), Host: r.Host, Body: string(b[:n]), Header: r.Header.Get("X-Test")}:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	leaf, err := ca.Leaf("upstream.test")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{leaf},
		NextProtos:   []string{"h2", "http/1.1"},
	}))
	return &upstream{ca: ca, srv: srv, ln: ln, gotReq: got}
}

func (u *upstream) addr() string { return u.ln.Addr().String() }

func (u *upstream) pool() *x509.CertPool { return u.ca.Pool() }

func (u *upstream) stop() { u.srv.Close(); u.ln.Close() }

type harness struct {
	cfg   config.Config
	store *audit.Store
	flows *audit.FlowRegistry
	srv   *Server
	up    *upstream
	dir   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Listen = "127.0.0.1:0"
	cfg.Output.Dir = dir
	ca, err := certs.LoadOrGenerateCA(filepath.Join(dir, "ca.key"), filepath.Join(dir, "ca.crt"), true)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CA = config.CAPaths{Key: filepath.Join(dir, "ca.key"), Cert: filepath.Join(dir, "ca.crt")}
	store, err := audit.OpenStore(dir, "events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	flows := audit.NewFlowRegistry(func(audit.Event) {}, cfg.Ports)
	up := startUpstream(t)
	srv := New(cfg, ca, store, flows)
	srv.OrigDst = func(*net.TCPConn) (string, error) { return up.addr(), nil }
	srv.UpstreamRoots = up.pool()
	go srv.ListenAndServe()
	waitFor(t, 2*time.Second, func() bool { return srv.Addr() != nil })
	return &harness{cfg: cfg, store: store, flows: flows, srv: srv, up: up, dir: dir}
}

func waitFor(t *testing.T, d time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func (h *harness) readEvents(t *testing.T) []audit.Event {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var evs []audit.Event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad jsonl: %v", err)
		}
		evs = append(evs, e)
	}
	return evs
}

func (h *harness) close(t *testing.T) {
	t.Helper()
	h.srv.Close()
	h.store.Close()
	h.up.stop()
}

func TestProxyEndToEndH1(t *testing.T) {
	h := newHarness(t)
	defer h.close(t)

	raw, err := net.DialTimeout("tcp", h.srv.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	src := raw.LocalAddr().(*net.TCPAddr)
	dstIP, dstPortS, _ := net.SplitHostPort(h.up.addr())
	var dstPort int
	fmt.Sscanf(dstPortS, "%d", &dstPort)
	h.flows.Add(audit.FlowKey{SrcIP: src.IP.String(), SrcPort: src.Port, DstIP: dstIP, DstPort: dstPort},
		audit.FlowInfo{PID: 31337, UID: 1000, Comm: "curl-test", Ts: time.Now()})

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: h.srv.ca.Pool(), ServerName: "upstream.test"},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				tc := tls.Client(raw, &tls.Config{ServerName: "upstream.test", RootCAs: h.srv.ca.Pool(), NextProtos: []string{"http/1.1"}})
				if err := tc.HandshakeContext(ctx); err != nil {
					return nil, err
				}
				return tc, nil
			},
		},
	}

	req, err := http.NewRequest("POST", "https://upstream.test/v1/echo?x=1", strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test", "hello")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := make([]byte, 256)
	n, _ := resp.Body.Read(body)
	if resp.StatusCode != 200 || string(body[:n]) != `{"ok":true}` {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body[:n])
	}

	select {
	case ur := <-h.up.gotReq:
		if ur.Method != "POST" || ur.Path != "/v1/echo?x=1" || ur.Host != "upstream.test" || ur.Body != `{"a":1}` || ur.Header != "hello" {
			t.Fatalf("upstream saw wrong request: %+v", ur)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never saw request")
	}

	waitFor(t, 2*time.Second, func() bool {
		for _, e := range h.readEvents(t) {
			if e.Type == audit.TypeHTTP && e.HTTP != nil && e.HTTP.Status == 200 {
				if e.PID == nil || *e.PID != 31337 || e.Comm != "curl-test" {
					t.Fatalf("attribution lost: %+v", e)
				}
				if e.SNI != "upstream.test" || e.Proto != "http/1.1" {
					t.Fatalf("sni/proto wrong: %q %q", e.SNI, e.Proto)
				}
				if e.HTTP.Method != "POST" || e.HTTP.Host != "upstream.test" || e.HTTP.Path != "/v1/echo?x=1" {
					t.Fatalf("http detail wrong: %+v", e.HTTP)
				}
				if e.HTTP.ReqBody == "" || e.HTTP.ReqBodyBytes != int64(len(`{"a":1}`)) {
					t.Fatalf("req body not captured: %+v", e.HTTP)
				}
				b, err := os.ReadFile(filepath.Join(h.dir, e.HTTP.ReqBody))
				if err != nil || string(b) != `{"a":1}` {
					t.Fatalf("req body file wrong: %v %q", err, b)
				}
				if e.HTTP.ResBody == "" || e.HTTP.ResBodyBytes != int64(len(`{"ok":true}`)) {
					t.Fatalf("res body not captured: %+v", e.HTTP)
				}
				return true
			}
		}
		return false
	})
}

func TestClientTLSFailureAlert(t *testing.T) {
	h := newHarness(t)
	defer h.close(t)

	wrongCA, err := certs.LoadOrGenerateCA(filepath.Join(t.TempDir(), "k2"), filepath.Join(t.TempDir(), "c2"), true)
	if err != nil {
		t.Fatal(err)
	}
	tc, err := tls.Dial("tcp", h.srv.Addr().String(), &tls.Config{
		ServerName: "upstream.test",
		RootCAs:    wrongCA.Pool(),
	})
	if err == nil {
		tc.Close()
		t.Fatal("handshake should have failed with wrong CA")
	}

	waitFor(t, 2*time.Second, func() bool {
		for _, e := range h.readEvents(t) {
			if e.Type == audit.TypeAlert && e.Alert != nil && e.Alert.Kind == audit.KindClientTLSFailed {
				return true
			}
		}
		return false
	})
}
