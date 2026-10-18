//go:build bpf

package bpf

import (
	"encoding/binary"
	"testing"
)

func TestVariableSetPatchesRodata(t *testing.T) {
	spec, err := loadFlowsSpec()
	if err != nil {
		t.Fatal(err)
	}
	v := spec.Variables["off_family"]
	if v == nil {
		t.Fatal("off_family variable missing from spec")
	}
	if err := patchRodata(spec, map[string]uint32{"off_family": 0x0A0B0C0D}); err != nil {
		t.Fatal(err)
	}

	ro := spec.Maps[".rodata"]
	if ro == nil {
		t.Fatal(".rodata map missing")
	}
	if len(ro.Contents) == 0 || ro.Contents[0].Value == nil {
		t.Fatal(".rodata contents empty")
	}
	data, ok := ro.Contents[0].Value.([]byte)
	if !ok {
		t.Fatal(".rodata value not bytes")
	}
	if int(v.Offset)+4 > len(data) {
		t.Fatalf("offset %d beyond .rodata size %d", v.Offset, len(data))
	}
	got := binary.NativeEndian.Uint32(data[v.Offset:])
	if got != 0x0A0B0C0D {
		t.Fatalf("Set did not patch .rodata: got %#x at offset %d", got, v.Offset)
	}
}
