package bpf

import (
	"testing"
)

const oldKernelFormat = `name: inet_sock_set_state
ID: 777
format:
	field:const void * skbaddr;	offset:8;	size:8;	signed:0;
	field:const void * skaddr;	offset:16;	size:8;	signed:0;
	field:int oldstate;	offset:24;	size:4;	signed:1;
	field:int newstate;	offset:28;	size:4;	signed:1;
	field:__u16 sport;	offset:32;	size:2;	signed:0;
	field:__u16 dport;	offset:34;	size:2;	signed:0;
	field:__u16 family;	offset:36;	size:2;	signed:0;
	field:__u16 protocol;	offset:38;	size:2;	signed:0;
	field:__u8 saddr[4];	offset:40;	size:4;	signed:0;
	field:__u8 daddr[4];	offset:44;	size:4;	signed:0;
	field:__u8 saddr_v6[16];	offset:48;	size:16;	signed:0;
	field:__u8 daddr_v6[16];	offset:64;	size:16;	signed:0;

print fmt: ...`

const newKernelFormat = `name: inet_sock_set_state
ID: 778
format:
	field:const void * skaddr;	offset:8;	size:8;	signed:0;
	field:int oldstate;	offset:16;	size:4;	signed:1;
	field:int newstate;	offset:20;	size:4;	signed:1;
	field:__u16 sport;	offset:24;	size:2;	signed:0;
	field:__u16 dport;	offset:26;	size:2;	signed:0;
	field:__u16 family;	offset:28;	size:2;	signed:0;
	field:__u16 protocol;	offset:30;	size:2;	signed:0;
	field:__u8 saddr[4];	offset:32;	size:4;	signed:0;
	field:__u8 daddr[4];	offset:36;	size:4;	signed:0;
	field:__u8 saddr_v6[16];	offset:40;	size:16;	signed:0;
	field:__u8 daddr_v6[16];	offset:56;	size:16;	signed:0;

print fmt: ...`

func TestParseTracepointFormatOldLayout(t *testing.T) {
	off, err := ParseTracepointFormat(oldKernelFormat)
	if err != nil {
		t.Fatal(err)
	}
	if off["newstate"] != 28 || off["sport"] != 32 || off["family"] != 36 {
		t.Fatalf("old layout offsets wrong: %+v", off)
	}
	if off["saddr_v6"] != 48 || off["daddr_v6"] != 64 {
		t.Fatalf("v6 offsets wrong: %+v", off)
	}
}

func TestParseTracepointFormatNewLayout(t *testing.T) {
	off, err := ParseTracepointFormat(newKernelFormat)
	if err != nil {
		t.Fatal(err)
	}
	if off["newstate"] != 20 || off["sport"] != 24 || off["family"] != 28 {
		t.Fatalf("new layout offsets wrong: %+v", off)
	}
	if off["saddr"] != 32 || off["daddr_v6"] != 56 {
		t.Fatalf("addr offsets wrong: %+v", off)
	}
}

func TestParseTracepointFormatMissingField(t *testing.T) {
	if _, err := ParseTracepointFormat("garbage without fields"); err == nil {
		t.Fatal("missing fields must error")
	}
	broken := "field:__u16 sport;	offset:32;	size:2;	signed:0;\n"
	if _, err := ParseTracepointFormat(broken); err == nil {
		t.Fatal("missing required fields must error")
	}
}

func TestBuildOffsetCfg(t *testing.T) {
	off, err := ParseTracepointFormat(newKernelFormat)
	if err != nil {
		t.Fatal(err)
	}
	cfg := BuildOffsetCfg(off)
	if cfg.Family != 28 || cfg.Newstate != 20 {
		t.Fatalf("cfg = %+v", cfg)
	}
	if cfg.Saddr6 != 40 || cfg.Daddr6 != 56 {
		t.Fatalf("cfg v6 = %+v", cfg)
	}
}
