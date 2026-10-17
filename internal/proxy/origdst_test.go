package proxy

import (
	"net"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestParseSockaddr4(t *testing.T) {
	sa := unix.RawSockaddrInet4{
		Family: unix.AF_INET,
		Port:   uint16(443&0xff<<8 | 443>>8),
		Addr:   [4]byte{127, 0, 0, 1},
	}
	b := (*(*[unsafe.Sizeof(sa)]byte)(unsafe.Pointer(&sa)))[:]
	ip, port, err := ParseSockaddr4(b)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.IPv4(127, 0, 0, 1)) || port != 443 {
		t.Fatalf("got %s:%d", ip, port)
	}

	if _, _, err := ParseSockaddr4(b[:8]); err == nil {
		t.Fatal("short buffer accepted")
	}
	sa.Family = unix.AF_INET6
	b2 := (*(*[unsafe.Sizeof(sa)]byte)(unsafe.Pointer(&sa)))[:]
	if _, _, err := ParseSockaddr4(b2); err == nil {
		t.Fatal("wrong family accepted")
	}
}

func TestParseSockaddr6(t *testing.T) {
	sa := unix.RawSockaddrInet6{
		Family: unix.AF_INET6,
		Port:   uint16(8443&0xff<<8 | 8443>>8),
	}
	copy(sa.Addr[:], net.IPv6loopback)
	b := (*(*[unsafe.Sizeof(sa)]byte)(unsafe.Pointer(&sa)))[:]
	ip, port, err := ParseSockaddr6(b)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.IPv6loopback) || port != 8443 {
		t.Fatalf("got [%s]:%d", ip, port)
	}
	if _, _, err := ParseSockaddr6(b[:16]); err == nil {
		t.Fatal("short buffer accepted")
	}
	sa.Family = unix.AF_INET
	if _, _, err := ParseSockaddr6(b); err == nil {
		t.Fatal("wrong family accepted")
	}
}

func TestOriginalDstNoPanicOnPlainConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tc := conn.(*net.TCPConn)

	got, err := OriginalDst(tc)
	if err == nil {
		host, _, perr := net.SplitHostPort(got)
		if perr != nil {
			t.Fatalf("non-error result not ip:port: %q", got)
		}
		if net.ParseIP(host) == nil {
			t.Fatalf("non-ip result: %q", got)
		}
	}
}
