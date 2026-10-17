package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hellsing-organization/mitm/internal/audit"
	"github.com/hellsing-organization/mitm/internal/certs"
	"github.com/hellsing-organization/mitm/internal/config"
	"golang.org/x/net/http2"
)

type sniCtxKey struct{}

type tlsMeta struct {
	SNI   string
	Proto string
}

func WithSNI(ctx context.Context, sni, proto string) context.Context {
	return context.WithValue(ctx, sniCtxKey{}, &tlsMeta{SNI: sni, Proto: proto})
}

func metaFrom(ctx context.Context) *tlsMeta {
	m, _ := ctx.Value(sniCtxKey{}).(*tlsMeta)
	return m
}

type connMeta struct {
	key     audit.FlowKey
	flowID  string
	origDst string
	sni     string
	proto   string
	src     string
	dst     string
	pending sync.WaitGroup
}

type Server struct {
	cfg           config.Config
	ca            *certs.CA
	store         *audit.Store
	flows         *audit.FlowRegistry
	OrigDst       func(*net.TCPConn) (string, error)
	UpstreamRoots *x509.CertPool

	ln        net.Listener
	closed    atomic.Bool
	wg        sync.WaitGroup
	connsMu   sync.Mutex
	conns     map[net.Conn]struct{}
	transport *http.Transport
	h2s       *http2.Server
}

func New(cfg config.Config, ca *certs.CA, store *audit.Store, flows *audit.FlowRegistry) *Server {
	s := &Server{
		cfg:     cfg,
		ca:      ca,
		store:   store,
		flows:   flows,
		OrigDst: OriginalDst,
		h2s:     &http2.Server{},
		conns:   make(map[net.Conn]struct{}),
	}
	s.transport = &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext:    s.dialUpstreamTLS,
		MaxIdleConns:      256,
		IdleConnTimeout:   90 * time.Second,
	}
	return s
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Listen, err)
	}
	s.connsMu.Lock()
	s.ln = ln
	s.connsMu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			if s.closed.Load() {
				return nil
			}
			return err
		}
		s.wg.Add(1)
		s.trackConn(c)
		go func() {
			defer s.wg.Done()
			s.handleConn(c)
		}()
	}
}

func (s *Server) trackConn(c net.Conn) {
	s.connsMu.Lock()
	s.conns[c] = struct{}{}
	s.connsMu.Unlock()
}

func (s *Server) untrackConn(c net.Conn) {
	s.connsMu.Lock()
	delete(s.conns, c)
	s.connsMu.Unlock()
}

func (s *Server) Addr() net.Addr {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

func (s *Server) Close() error {
	s.closed.Store(true)
	s.connsMu.Lock()
	if s.ln != nil {
		s.ln.Close()
	}
	for c := range s.conns {
		c.Close()
	}
	s.connsMu.Unlock()
	s.wg.Wait()
	s.transport.CloseIdleConnections()
	return nil
}

func (s *Server) handleConn(c net.Conn) {
	defer s.untrackConn(c)
	defer c.Close()
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	origDst, err := s.OrigDst(tc)
	if err != nil {
		return
	}
	srcIP, srcPortStr, err := net.SplitHostPort(tc.RemoteAddr().String())
	if err != nil {
		return
	}
	srcPort, _ := strconv.Atoi(srcPortStr)
	dstIP, dstPortStr, err := net.SplitHostPort(origDst)
	if err != nil {
		return
	}
	dstPort, _ := strconv.Atoi(dstPortStr)
	key := audit.FlowKey{SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort}
	meta := &connMeta{
		key:     key,
		origDst: origDst,
		src:     tc.RemoteAddr().String(),
		dst:     origDst,
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%+v", key)))
	meta.flowID = hex.EncodeToString(sum[:])[:16]

	defer s.flows.Release(key)

	tc.SetReadDeadline(time.Now().Add(30 * time.Second))
	tlsConn := tls.Server(tc, &tls.Config{
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hi.ServerName
			if host == "" {
				host = dstIP
			}
			return s.ca.TLSCert(host)
		},
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		s.emitClientTLSFailure(meta, err)
		return
	}
	tc.SetReadDeadline(time.Time{})
	cs := tlsConn.ConnectionState()
	meta.sni = cs.ServerName
	meta.proto = cs.NegotiatedProtocol
	if meta.proto == "" {
		meta.proto = "http/1.1"
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serveHTTP(w, r, meta)
	})

	if meta.proto == "h2" {
		s.h2s.ServeConn(tlsConn, &http2.ServeConnOpts{Handler: handler})
		return
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 60 * time.Second,
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, connMetaKey{}, meta)
		},
	}
	connClosed := make(chan struct{})
	var connClosedOnce sync.Once
	srv.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed || state == http.StateHijacked {
			connClosedOnce.Do(func() { close(connClosed) })
		}
	}
	srv.Serve(&oneConnListener{c: tlsConn, closed: connClosed})
	meta.pending.Wait()
}

type oneConnListener struct {
	c      net.Conn
	done   bool
	closed <-chan struct{}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.done {
		<-l.closed
		return nil, net.ErrClosed
	}
	l.done = true
	return l.c, nil
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.c.LocalAddr() }

type connMetaKey struct{}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request, meta *connMeta) {
	if meta == nil {
		m, _ := r.Context().Value(connMetaKey{}).(*connMeta)
		meta = m
	}
	if meta == nil {
		http.Error(w, "no conn meta", http.StatusBadGateway)
		return
	}

	fi := s.flows.Take(meta.key)
	var pid *int32
	var uid *uint32
	comm := ""
	if fi != nil {
		p, u := fi.PID, fi.UID
		pid, uid, comm = &p, &u, fi.Comm
	}

	detail := &audit.HTTPDetail{
		Method:     r.Method,
		Host:       r.Host,
		Path:       r.URL.RequestURI(),
		ReqHeaders: headersToMap(r.Header),
	}

	maxBody := s.cfg.Capture.MaxBodyBytes
	captureReq := s.cfg.Capture.Bodies && s.cfg.MatchComm(comm) &&
		s.cfg.MatchDomain(r.Host) && s.cfg.MatchContentType(r.Header.Get("Content-Type"))
	var reqCap *audit.LimitBuf
	if captureReq && r.Body != nil {
		reqCap = audit.NewLimitBuf(maxBody)
		body := r.Body
		r.Body = io.NopCloser(io.TeeReader(body, reqCap))
	}

	ctx := WithSNI(r.Context(), meta.sni, meta.proto)
	out := r.Clone(ctx)
	out.RequestURI = ""
	out.URL.Scheme = "https"
	out.URL.Host = meta.origDst

	resp, err := s.transport.RoundTrip(out)
	if err != nil {
		detail.Err = err.Error()
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, "mitm-audit: upstream error")
		s.finishEvent(meta, pid, uid, comm, detail, reqCap, nil, r.Header.Get("Content-Encoding"))
		return
	}
	defer resp.Body.Close()

	detail.Status = resp.StatusCode
	detail.ResHeaders = headersToMap(resp.Header)

	if resp.StatusCode == http.StatusSwitchingProtocols {
		s.handleUpgrade(w, r, resp, meta, pid, uid, comm, detail, reqCap)
		return
	}

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	captureRes := s.cfg.Capture.Bodies && s.cfg.MatchComm(comm) &&
		s.cfg.MatchDomain(r.Host) && s.cfg.MatchContentType(resp.Header.Get("Content-Type"))
	var resCap *audit.LimitBuf
	rc := http.NewResponseController(w)
	if captureRes {
		resCap = audit.NewLimitBuf(maxBody)
		buf := make([]byte, 16*1024)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				resCap.Write(buf[:n])
				if _, werr := w.Write(buf[:n]); werr != nil {
					break
				}
				rc.Flush()
			}
			if rerr != nil {
				break
			}
		}
	} else {
		io.Copy(w, resp.Body)
		rc.Flush()
	}

	s.finishEvent(meta, pid, uid, comm, detail, reqCap, resCap, r.Header.Get("Content-Encoding"))
}

func (s *Server) finishEvent(meta *connMeta, pid *int32, uid *uint32, comm string,
	detail *audit.HTTPDetail, reqCap, resCap *audit.LimitBuf, reqEncoding string) {

	if reqCap != nil && reqCap.Total() > 0 {
		if rel, err := s.store.SaveBody("req", reqCap.Bytes()); err == nil {
			detail.ReqBody = rel
			detail.ReqBodyBytes = reqCap.Total()
			if reqCap.Truncated() {
				detail.Truncated = true
			}
			if d, ok := audit.DecodeBody(reqEncoding, reqCap.Bytes()); ok {
				s.store.SaveBody("req.decoded", d)
			}
		}
	}
	if resCap != nil && resCap.Total() > 0 {
		if rel, err := s.store.SaveBody("res", resCap.Bytes()); err == nil {
			detail.ResBody = rel
			detail.ResBodyBytes = resCap.Total()
			if resCap.Truncated() {
				detail.Truncated = true
			}
		}
	}
	_ = s.store.WriteEvent(audit.Event{
		Ts:     time.Now().UTC(),
		Type:   audit.TypeHTTP,
		FlowID: meta.flowID,
		PID:    pid,
		UID:    uid,
		Comm:   comm,
		Src:    meta.src,
		Dst:    meta.dst,
		SNI:    meta.sni,
		Proto:  meta.proto,
		HTTP:   detail,
	})
}

func (s *Server) emitClientTLSFailure(meta *connMeta, err error) {
	var pid *int32
	var uid *uint32
	comm := ""
	if fi := s.flows.Take(meta.key); fi != nil {
		p, u := fi.PID, fi.UID
		pid, uid, comm = &p, &u, fi.Comm
	}
	s.store.WriteEvent(audit.Event{
		Ts:     time.Now().UTC(),
		Type:   audit.TypeAlert,
		FlowID: meta.flowID,
		PID:    pid,
		UID:    uid,
		Comm:   comm,
		Src:    meta.src,
		Dst:    meta.dst,
		Alert: &audit.AlertDetail{
			Kind: audit.KindClientTLSFailed,
			Note: "client rejected our CA (likely cert pinning): " + err.Error(),
		},
	})
}

func (s *Server) handleUpgrade(w http.ResponseWriter, r *http.Request, resp *http.Response,
	meta *connMeta, pid *int32, uid *uint32, comm string, detail *audit.HTTPDetail, reqCap *audit.LimitBuf) {

	detail.Note = "websocket upgrade, frames not parsed"
	meta.pending.Add(1)
	defer meta.pending.Done()
	rc := http.NewResponseController(w)
	clientConn, clientBuf, err := rc.Hijack()
	if err == nil {
		clientBuf.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
		for k, vv := range resp.Header {
			for _, v := range vv {
				clientBuf.WriteString(k + ": " + v + "\r\n")
			}
		}
		clientBuf.WriteString("\r\n")
		clientBuf.Flush()

		upDone := make(chan struct{})
		go func() {
			io.Copy(clientConn, resp.Body)
			clientConn.Close()
			close(upDone)
		}()
		type readWriter interface {
			io.Reader
			io.Writer
		}
		if ub, ok := resp.Body.(readWriter); ok {
			io.Copy(ub, clientBuf)
		}
		<-upDone
	}
	s.finishEvent(meta, pid, uid, comm, detail, reqCap, nil, r.Header.Get("Content-Encoding"))
}

func headersToMap(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	m := make(map[string]string, len(h))
	for k, vv := range h {
		out := ""
		for i, v := range vv {
			if i > 0 {
				out += "; "
			}
			out += v
		}
		m[k] = out
	}
	return m
}
