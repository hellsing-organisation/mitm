package bpf

import (
	"encoding/binary"
	"testing"
)

func TestParseFlowEvent(t *testing.T) {
	b := make([]byte, SizeofFlowEvent)
	binary.LittleEndian.PutUint64(b[0:8], 1234567890)
	binary.LittleEndian.PutUint32(b[8:12], 4242)
	binary.LittleEndian.PutUint32(b[12:16], 1000)
	copy(b[16:26], "curl\x00\x00\x00\x00\x00\x00")
	binary.LittleEndian.PutUint16(b[32:34], 2)
	binary.LittleEndian.PutUint16(b[34:36], 44120)
	binary.LittleEndian.PutUint16(b[36:38], 443)
	copy(b[40:44], []byte{127, 0, 0, 1})
	copy(b[44:48], []byte{93, 184, 216, 34})

	ev, err := ParseFlowEvent(b)
	if err != nil {
		t.Fatal(err)
	}
	if ev.PID != 4242 || ev.UID != 1000 || ev.Comm != "curl" {
		t.Fatalf("got %+v", ev)
	}
	if ev.Sport != 44120 || ev.Dport != 443 || ev.Family != 2 {
		t.Fatalf("got %+v", ev)
	}
	if ev.SrcIP().String() != "127.0.0.1" || ev.DstIP().String() != "93.184.216.34" {
		t.Fatalf("ips: %s %s", ev.SrcIP(), ev.DstIP())
	}

	v6 := make([]byte, SizeofFlowEvent)
	binary.LittleEndian.PutUint16(v6[32:34], 10)
	copy(v6[48:64], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(v6[64:80], []byte{0x20, 0x01, 0x0d, 0xb8})
	ev6, err := ParseFlowEvent(v6)
	if err != nil {
		t.Fatal(err)
	}
	if ev6.SrcIP().String() != "::1" {
		t.Fatalf("v6 src: %s", ev6.SrcIP())
	}

	if _, err := ParseFlowEvent(b[:10]); err == nil {
		t.Fatal("short buffer accepted")
	}
	binary.LittleEndian.PutUint16(b[32:34], 99)
	if _, err := ParseFlowEvent(b); err == nil {
		t.Fatal("implausible family accepted")
	}
}

func TestLoadDisabled(t *testing.T) {
	if _, err := Load(nil, false); err != ErrDisabled {
		t.Fatalf("want ErrDisabled, got %v", err)
	}
}

func TestLoadEnabledWithoutObjects(t *testing.T) {
	stop, err := Load(func(FlowEvent) {}, true)
	if err == nil {
		stop()
		t.Fatal("expected error without built objects or privileges")
	}
}
