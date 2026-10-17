package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	soOriginalDst   = 0x50
	ip6tOriginalDst = 0x50
	sizeofSockaddr4 = 16
	sizeofSockaddr6 = 28
)

func OriginalDst(c *net.TCPConn) (string, error) {
	file, err := c.File()
	if err != nil {
		return "", fmt.Errorf("conn file: %w", err)
	}
	defer file.Close()
	fd := int(file.Fd())

	buf4 := make([]byte, sizeofSockaddr4)
	if err := getsockopt(fd, unix.SOL_IP, soOriginalDst, unsafe.Pointer(&buf4[0]), sizeofSockaddr4); err == nil {
		ip, port, perr := ParseSockaddr4(buf4)
		if perr == nil {
			return net.JoinHostPort(ip.String(), fmt.Sprint(port)), nil
		}
	}

	buf6 := make([]byte, sizeofSockaddr6)
	if err := getsockopt(fd, unix.SOL_IPV6, ip6tOriginalDst, unsafe.Pointer(&buf6[0]), sizeofSockaddr6); err == nil {
		ip, port, perr := ParseSockaddr6(buf6)
		if perr == nil {
			return net.JoinHostPort(ip.String(), fmt.Sprint(port)), nil
		}
	}
	return "", fmt.Errorf("original destination unavailable (connection not NAT-redirected?)")
}

func getsockopt(fd int, level, opt int, ptr unsafe.Pointer, length int) error {
	mlen := uint32(length)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(ptr), uintptr(unsafe.Pointer(&mlen)), 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func ParseSockaddr4(b []byte) (net.IP, uint16, error) {
	if len(b) < sizeofSockaddr4 {
		return nil, 0, fmt.Errorf("sockaddr4 too short: %d", len(b))
	}
	family := binary.LittleEndian.Uint16(b[0:2])
	if family != unix.AF_INET {
		return nil, 0, fmt.Errorf("not AF_INET: %d", family)
	}
	port := binary.BigEndian.Uint16(b[2:4])
	ip := net.IP(append([]byte(nil), b[4:8]...))
	return ip, port, nil
}

func ParseSockaddr6(b []byte) (net.IP, uint16, error) {
	if len(b) < sizeofSockaddr6 {
		return nil, 0, fmt.Errorf("sockaddr6 too short: %d", len(b))
	}
	family := binary.LittleEndian.Uint16(b[0:2])
	if family != unix.AF_INET6 {
		return nil, 0, fmt.Errorf("not AF_INET6: %d", family)
	}
	port := binary.BigEndian.Uint16(b[2:4])
	ip := net.IP(append([]byte(nil), b[8:24]...))
	return ip, port, nil
}
