package audit

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestLimitBuf(t *testing.T) {
	lb := NewLimitBuf(4)
	if n, err := lb.Write([]byte("hello world")); n != 11 || err != nil {
		t.Fatalf("write returned (%d, %v)", n, err)
	}
	if string(lb.Bytes()) != "hell" {
		t.Fatalf("stored = %q", lb.Bytes())
	}
	if lb.Total() != 11 {
		t.Fatalf("total = %d", lb.Total())
	}
	if !lb.Truncated() {
		t.Fatal("truncated flag missing")
	}
	lb2 := NewLimitBuf(16)
	lb2.Write([]byte("short"))
	if lb2.Truncated() {
		t.Fatal("false truncation")
	}
}

func TestCopyCapped(t *testing.T) {
	payload := strings.Repeat("x", 1000)
	lb := NewLimitBuf(100)
	var dst bytes.Buffer
	n, err := CopyCapped(&dst, strings.NewReader(payload), lb)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("copied %d, want %d", n, len(payload))
	}
	if dst.Len() != len(payload) {
		t.Fatalf("dst got %d bytes, want full %d", dst.Len(), len(payload))
	}
	if lb.Total() != int64(len(payload)) || !lb.Truncated() || len(lb.Bytes()) != 100 {
		t.Fatalf("limitbuf wrong: total=%d trunc=%v stored=%d", lb.Total(), lb.Truncated(), len(lb.Bytes()))
	}
}

func TestDecodeBody(t *testing.T) {
	plain := []byte(`{"hello":"world"}`)

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(plain)
	zw.Close()
	out, ok := DecodeBody("gzip", gz.Bytes())
	if !ok || !bytes.Equal(out, plain) {
		t.Fatalf("gzip decode failed: ok=%v out=%q", ok, out)
	}

	var br bytes.Buffer
	bw := brotli.NewWriter(&br)
	bw.Write(plain)
	bw.Close()
	out, ok = DecodeBody("br", br.Bytes())
	if !ok || !bytes.Equal(out, plain) {
		t.Fatalf("brotli decode failed: ok=%v out=%q", ok, out)
	}

	var fl bytes.Buffer
	fw, _ := flate.NewWriter(&fl, 5)
	fw.Write(plain)
	fw.Close()
	out, ok = DecodeBody("deflate", fl.Bytes())
	if !ok || !bytes.Equal(out, plain) {
		t.Fatalf("deflate decode failed: ok=%v out=%q", ok, out)
	}

	raw := []byte("raw-bytes")
	out, ok = DecodeBody("identity", raw)
	if ok || !bytes.Equal(out, raw) {
		t.Fatalf("identity must pass through unchanged with ok=false, got ok=%v", ok)
	}
	out, ok = DecodeBody("zstd", raw)
	if ok || !bytes.Equal(out, raw) {
		t.Fatalf("unknown encoding must pass through with ok=false")
	}

	out, ok = DecodeBody("gzip", []byte("not-gzip"))
	if ok {
		t.Fatal("broken gzip must report ok=false, not garbage")
	}
	if !bytes.Equal(out, []byte("not-gzip")) {
		t.Fatal("broken input should be returned as-is")
	}

	_ = io.Discard
}
