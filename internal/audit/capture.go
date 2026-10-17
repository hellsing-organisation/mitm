package audit

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

type LimitBuf struct {
	b     []byte
	limit int64
	total int64
}

func NewLimitBuf(limit int64) *LimitBuf {
	return &LimitBuf{limit: limit}
}

func (l *LimitBuf) Write(p []byte) (int, error) {
	l.total += int64(len(p))
	if room := l.limit - int64(len(l.b)); room > 0 {
		if int64(len(p)) < room {
			room = int64(len(p))
		}
		l.b = append(l.b, p[:room]...)
	}
	return len(p), nil
}

func (l *LimitBuf) Bytes() []byte   { return l.b }
func (l *LimitBuf) Total() int64    { return l.total }
func (l *LimitBuf) Truncated() bool { return l.total > l.limit }

func CopyCapped(dst io.Writer, src io.Reader, lb *LimitBuf) (int64, error) {
	return io.Copy(io.MultiWriter(dst, lb), src)
}

func DecodeBody(contentEncoding string, raw []byte) (out []byte, decoded bool) {
	enc := strings.TrimSpace(strings.ToLower(contentEncoding))
	switch enc {
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return raw, false
		}
		d, err := io.ReadAll(zr)
		if err != nil {
			return raw, false
		}
		return d, true
	case "deflate":
		fr := flate.NewReader(bytes.NewReader(raw))
		d, err := io.ReadAll(fr)
		if err != nil {
			return raw, false
		}
		return d, true
	case "br":
		d, err := io.ReadAll(brotli.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return raw, false
		}
		return d, true
	default:
		return raw, false
	}
}
