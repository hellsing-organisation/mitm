//go:build bpf

package bpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:embed flows.bpf.o
var flowsObj []byte

var tracefsCandidates = []string{
	"/sys/kernel/tracing",
	"/sys/kernel/debug/tracing",
}

var tracepointGroups = []string{"sock", "inet"}

type flowsObjects struct {
	InetSockSetState *ebpf.Program `ebpf:"inet_sock_set_state"`
	Events           *ebpf.Map     `ebpf:"events"`
}

func loadFlowsSpec() (*ebpf.CollectionSpec, error) {
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(flowsObj))
}

// loadInfo records what the loader discovered and rewrote, surfaced in the
// daemon's startup event for diagnosability.
var loadInfo string

// LoadInfo returns diagnostics from the last successful Load.
func LoadInfo() string { return loadInfo }

// discoverTracepoint locates the inet_sock_set_state tracepoint across kernel
// versions: group "sock" (6.18+) or "inet" (pre-6.18). Returns the group and
// the path of its format file.
func discoverTracepoint() (group, formatPath string, err error) {
	for _, root := range tracefsCandidates {
		for _, g := range tracepointGroups {
			p := filepath.Join(root, "events", g, "inet_sock_set_state", "format")
			if _, serr := os.Stat(p); serr == nil {
				return g, p, nil
			}
		}
	}
	return "", "", fmt.Errorf("tracepoint inet_sock_set_state not found under %v (kernel without tracing?)", tracefsCandidates)
}

func Load(onEvent func(FlowEvent), enabled bool) (stop func() error, err error) {
	if !enabled {
		return nil, ErrDisabled
	}
	group, formatPath, err := discoverTracepoint()
	if err != nil {
		return nil, err
	}
	formatBytes, err := os.ReadFile(formatPath)
	if err != nil {
		return nil, fmt.Errorf("read tracepoint format: %w", err)
	}
	off, err := ParseTracepointFormat(string(formatBytes))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", formatPath, err)
	}
	loadInfo = fmt.Sprintf("group=%s format=%s offsets=%v", group, formatPath, off)

	spec, err := loadFlowsSpec()
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}
	for name, val := range ConstantsFromOffsets(off) {
		v, ok := spec.Variables[name]
		if !ok {
			return nil, fmt.Errorf("bpf object lacks layout variable %q", name)
		}
		if err := v.Set(val); err != nil {
			return nil, fmt.Errorf("set %s: %w", name, err)
		}
	}
	if err := patchRodata(spec, ConstantsFromOffsets(off)); err != nil {
		return nil, err
	}
	var obj flowsObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	lnk, err := link.Tracepoint(group, "inet_sock_set_state", obj.InetSockSetState, nil)
	if err != nil {
		obj.InetSockSetState.Close()
		obj.Events.Close()
		return nil, fmt.Errorf("attach tracepoint %s/inet_sock_set_state: %w", group, err)
	}

	rd, err := ringbuf.NewReader(obj.Events)
	if err != nil {
		lnk.Close()
		obj.InetSockSetState.Close()
		obj.Events.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			rec, err := rd.Read()
			if err != nil {
				if !errors.Is(err, ringbuf.ErrClosed) {
					fmt.Fprintf(os.Stderr, "mitmd: ringbuf read: %v\n", err)
				}
				return
			}
			if ev, perr := ParseFlowEvent(rec.RawSample); perr == nil {
				onEvent(ev)
			}
		}
	}()

	stop = func() error {
		rd.Close()
		<-done
		lnk.Close()
		obj.InetSockSetState.Close()
		obj.Events.Close()
		return nil
	}
	return stop, nil
}

// patchRodata writes the layout offsets into the .rodata image that is
// actually loaded into the kernel. cilium's VariableSpec.Set does not mutate
// MapSpec.Contents for constants, so without this the program would run with
// compile-time default offsets.
func patchRodata(spec *ebpf.CollectionSpec, cs map[string]uint32) error {
	ro := spec.Maps[".rodata"]
	if ro == nil || len(ro.Contents) == 0 || ro.Contents[0].Value == nil {
		return fmt.Errorf("bpf object has no .rodata contents to patch")
	}
	data, ok := ro.Contents[0].Value.([]byte)
	if !ok {
		return fmt.Errorf(".rodata contents not bytes")
	}
	for name, val := range cs {
		v, ok := spec.Variables[name]
		if !ok {
			return fmt.Errorf("bpf object lacks layout variable %q", name)
		}
		if int(v.Offset)+4 > len(data) {
			return fmt.Errorf("variable %s offset %d beyond .rodata size %d", name, v.Offset, len(data))
		}
		binary.NativeEndian.PutUint32(data[v.Offset:], val)
	}
	return nil
}
