package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
)

const SizeofFlowEvent = 80

var (
	ErrDisabled = errors.New("bpf flow probe disabled by caller")
	ErrNotBuilt = errors.New("bpf objects not built (run make bpf)")
)

var fieldRe = regexp.MustCompile(`field:([^\s;]+(?:\s+[^\s;]+)?)\s+([^\s;]+)(?:\[\d+\])?;\s*offset:(\d+);\s*size:(\d+)`)

var requiredFields = []string{
	"oldstate", "newstate", "sport", "dport", "family", "protocol",
	"saddr", "daddr", "saddr_v6", "daddr_v6",
}

// ParseTracepointFormat extracts field-name → byte-offset from the textual
// "format" file of a tracepoint. Layouts drift across kernel versions (e.g.
// inet_sock_set_state moved groups and lost skbaddr in 6.18), so offsets are
// discovered at load time instead of hardcoded.
func ParseTracepointFormat(format string) (map[string]int, error) {
	off := make(map[string]int)
	for _, m := range fieldRe.FindAllStringSubmatch(format, -1) {
		name := m[2]
		if i := indexByte(name, '['); i >= 0 {
			name = name[:i]
		}
		o, err := strconv.Atoi(m[3])
		if err != nil {
			continue
		}
		off[name] = o
	}
	if len(off) == 0 {
		return nil, fmt.Errorf("no fields parsed from tracepoint format")
	}
	for _, f := range requiredFields {
		if _, ok := off[f]; !ok {
			return nil, fmt.Errorf("tracepoint format missing field %q", f)
		}
	}
	return off, nil
}

// ConstantsFromOffsets maps parsed offsets onto the volatile-const names
// consumed by flows.bpf.c (rewritten into .rodata before load).
func ConstantsFromOffsets(off map[string]int) map[string]uint32 {
	return map[string]uint32{
		"off_oldstate": uint32(off["oldstate"]),
		"off_newstate": uint32(off["newstate"]),
		"off_protocol": uint32(off["protocol"]),
		"off_sport":    uint32(off["sport"]),
		"off_dport":    uint32(off["dport"]),
		"off_family":   uint32(off["family"]),
		"off_saddr":    uint32(off["saddr"]),
		"off_daddr":    uint32(off["daddr"]),
		"off_saddr6":   uint32(off["saddr_v6"]),
		"off_daddr6":   uint32(off["daddr_v6"]),
	}
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

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
