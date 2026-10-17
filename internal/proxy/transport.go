package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func (s *Server) dialUpstreamTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{
		Timeout: 15 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, s.cfg.Redirect.Mark)
			})
			if serr != nil && !isPermission(serr) {
				return serr
			}
			return nil
		},
	}
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	sni := ""
	if m := metaFrom(ctx); m != nil && m.SNI != "" {
		sni = m.SNI
	} else if host, _, herr := net.SplitHostPort(addr); herr == nil {
		sni = host
	}

	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: sni,
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
		RootCAs:    s.UpstreamRoots,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tlsConn, nil
}

func isPermission(err error) bool {
	return err == unix.EPERM || err == unix.EACCES
}
