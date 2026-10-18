//go:build bpf

package bpf

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

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
	Cfg              *ebpf.Map     `ebpf:"cfg"`
	Stats            *ebpf.Map     `ebpf:"stats"`
	Diag             *ebpf.Map     `ebpf:"diag"`
}

func loadFlowsSpec() (*ebpf.CollectionSpec, error) {
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(flowsObj))
}

// loadInfo records what the loader discovered and injected, surfaced in the
// daemon's startup event for diagnosability.
var loadInfo string

// LoadInfo returns diagnostics from the last Load.
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

// Stats returns the summed per-CPU counters from the running probe.
func (p *Probe) ReadStats() (Stats, error) {
	var out Stats
	ncpu := runtime.NumCPU()
	for idx, dst := range []*uint64{&out.Calls, &out.Syn, &out.FamilyOK, &out.RbFail} {
		vals := make([]uint64, ncpu)
		key := uint32(idx)
		if err := p.stats.Lookup(&key, &vals); err != nil {
			return Stats{}, err
		}
		for _, v := range vals {
			*dst += v
		}
	}
	return out, nil
}

func (p *Probe) ReadDiag() (Diag, error) {
	zero := uint32(0)
	var d Diag
	if err := p.diag.Lookup(&zero, &d); err != nil {
		return Diag{}, err
	}
	return d, nil
}

// Probe is a handle on the loaded eBPF flow probe.
type Probe struct {
	stop  func() error
	stats *ebpf.Map
	diag  *ebpf.Map
}

func (p *Probe) Stop() error { return p.stop() }

func Load(onEvent func(FlowEvent), enabled bool) (*Probe, error) {
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
	cfgVal := BuildOffsetCfg(off)
	loadInfo = fmt.Sprintf("group=%s format=%s cfg=%+v", group, formatPath, cfgVal)

	spec, err := loadFlowsSpec()
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}
	var obj flowsObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	zero := uint32(0)
	if err := obj.Cfg.Put(&zero, cfgVal); err != nil {
		obj.InetSockSetState.Close()
		obj.Events.Close()
		obj.Cfg.Close()
		obj.Stats.Close()
		obj.Diag.Close()
		return nil, fmt.Errorf("inject layout offsets: %w", err)
	}

	lnk, err := link.Tracepoint(group, "inet_sock_set_state", obj.InetSockSetState, nil)
	if err != nil {
		obj.InetSockSetState.Close()
		obj.Events.Close()
		obj.Cfg.Close()
		obj.Stats.Close()
		obj.Diag.Close()
		return nil, fmt.Errorf("attach tracepoint %s/inet_sock_set_state: %w", group, err)
	}
	rd, err := ringbuf.NewReader(obj.Events)
	if err != nil {
		lnk.Close()
		obj.InetSockSetState.Close()
		obj.Events.Close()
		obj.Cfg.Close()
		obj.Stats.Close()
		obj.Diag.Close()
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
			} else {
				fmt.Fprintf(os.Stderr, "mitmd: parse flow event: %v\n", perr)
			}
		}
	}()

	stop := func() error {
		rd.Close()
		<-done
		lnk.Close()
		obj.InetSockSetState.Close()
		obj.Events.Close()
		obj.Cfg.Close()
		obj.Stats.Close()
		obj.Diag.Close()
		return nil
	}
	return &Probe{stop: stop, stats: obj.Stats, diag: obj.Diag}, nil
}
