//go:build bpf

package bpf

import (
	"bytes"
	_ "embed"
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

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(flowsObj))
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
