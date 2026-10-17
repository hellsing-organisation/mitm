package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const SizeofFlowEvent = 80

var (
	ErrDisabled = errors.New("bpf flow probe disabled by caller")
	ErrNotBuilt = errors.New("bpf objects not built (run make bpf)")
)

type FlowEvent struct {
	Ts     uint64
	PID    uint32
	UID    uint32
	Comm   string
	Family uint16
	Sport  uint16
	Dport  uint16
	Saddr  [4]byte
	Daddr  [4]byte
	Saddr6 [16]byte
	Daddr6 [16]byte
}

func (e FlowEvent) SrcIP() net.IP {
	if e.Family == 2 {
		return net.IP(e.Saddr[:])
	}
	return net.IP(e.Saddr6[:])
}

func (e FlowEvent) DstIP() net.IP {
	if e.Family == 2 {
		return net.IP(e.Daddr[:])
	}
	return net.IP(e.Daddr6[:])
}

func ParseFlowEvent(b []byte) (FlowEvent, error) {
	if len(b) < SizeofFlowEvent {
		return FlowEvent{}, fmt.Errorf("flow event too short: %d", len(b))
	}
	var e FlowEvent
	e.Ts = binary.LittleEndian.Uint64(b[0:8])
	e.PID = binary.LittleEndian.Uint32(b[8:12])
	e.UID = binary.LittleEndian.Uint32(b[12:16])
	e.Comm = cstr(b[16:32])
	e.Family = binary.LittleEndian.Uint16(b[32:34])
	e.Sport = binary.LittleEndian.Uint16(b[34:36])
	e.Dport = binary.LittleEndian.Uint16(b[36:38])
	copy(e.Saddr[:], b[40:44])
	copy(e.Daddr[:], b[44:48])
	copy(e.Saddr6[:], b[48:64])
	copy(e.Daddr6[:], b[64:80])
	if e.Family != 2 && e.Family != 10 {
		return FlowEvent{}, fmt.Errorf("implausible family %d (tracepoint layout mismatch?)", e.Family)
	}
	return e, nil
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
