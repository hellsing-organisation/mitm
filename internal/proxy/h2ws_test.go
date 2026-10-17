package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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
	"golang.org/x/net/http2"
)

func TestProxyH2Client(t *testing.T) {
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
		audit.FlowInfo{PID: 42, UID: 7, Comm: "h2-client", Ts: time.Now()})

	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			tc := tls.Client(raw, &tls.Config{
				ServerName: "upstream.test",
				RootCAs:    h.srv.ca.Pool(),
				NextProtos: []string{"h2"},
			})
			if err := tc.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return tc, nil
		},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	req, _ := http.NewRequest("GET", "https://upstream.test/v1/echo?x=2", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("client did not negotiate h2: %s", resp.Proto)
	}

	waitFor(t, 3*time.Second, func() bool {
		for _, e := range h.readEvents(t) {
			if e.Type == audit.TypeHTTP && e.HTTP != nil && e.HTTP.Status == 200 {
				if e.Proto != "h2" {
					t.Fatalf("event proto = %q, want h2", e.Proto)
				}
				if e.PID == nil || *e.PID != 42 {
					t.Fatalf("attribution lost: %+v", e)
				}
				return true
			}
		}
		return false
	})
}

func TestWebSocketRelay(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Listen = "127.0.0.1:0"
	cfg.Output.Dir = dir
	ca, err := certs.LoadOrGenerateCA(filepath.Join(dir, "ca.key"), filepath.Join(dir, "ca.crt"), true)
	if err != nil {
		t.Fatal(err)
	}
	store, err := audit.OpenStore(dir, "events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	flows := audit.NewFlowRegistry(func(audit.Event) {}, cfg.Ports)

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upCA, _ := certs.LoadOrGenerateCA(filepath.Join(dir, "uk"), filepath.Join(dir, "uc"), true)
	upLeaf, _ := upCA.Leaf("upstream.test")
	upMux := http.NewServeMux()
	upMux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			w.WriteHeader(400)
			return
		}
		hj := w.(http.Hijacker)
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		buf.Flush()
		b := make([]byte, 4)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, b); err != nil {
			fmt.Fprint(conn, "read-failed")
			return
		}
		conn.Write(append([]byte("echo:"), b...))
	})
	upSrv := &http.Server{Handler: upMux, ReadHeaderTimeout: 5 * time.Second}
	go upSrv.Serve(tls.NewListener(upLn, &tls.Config{Certificates: []tls.Certificate{upLeaf}}))
	defer upSrv.Close()

	srv := New(cfg, ca, store, flows)
	srv.OrigDst = func(*net.TCPConn) (string, error) { return upLn.Addr().String(), nil }
	srv.UpstreamRoots = upCA.Pool()
	go srv.ListenAndServe()
	waitFor(t, 2*time.Second, func() bool { return srv.Addr() != nil })
	defer srv.Close()
	defer store.Close()

	tc, err := tls.Dial("tcp", srv.Addr().String(), &tls.Config{
		ServerName: "upstream.test",
		RootCAs:    ca.Pool(),
		NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	fmt.Fprintf(tc, "GET /ws HTTP/1.1\r\nHost: upstream.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	fmt.Fprint(tc, "ping")

	br := bufio.NewReader(tc)
	tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("no 101: %q", statusLine)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	msg, err := br.ReadString('\n')
	if err != nil && msg == "" {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "echo:ping") {
		t.Fatalf("relay wrong: %q", msg)
	}

	waitFor(t, 3*time.Second, func() bool {
		for _, e := range h2readEvents(t, dir) {
			if e.Type == audit.TypeHTTP && e.HTTP != nil && e.HTTP.Status == 101 {
				if e.HTTP.Note == "" {
					t.Fatal("expected websocket note")
				}
				return true
			}
		}
		return false
	})
}

func h2readEvents(t *testing.T, dir string) []audit.Event {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return nil
	}
	var evs []audit.Event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e audit.Event
		if json.Unmarshal([]byte(line), &e) == nil {
			evs = append(evs, e)
		}
	}
	return evs
}
