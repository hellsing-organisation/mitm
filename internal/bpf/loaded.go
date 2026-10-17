//go:build bpf

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:embed flows.bpf.o
var flowsObj []byte

type flowsObjects struct {
	InetSockSetState *ebpf.Program `ebpf:"inet_sock_set_state"`
	Events           *ebpf.Map     `ebpf:"events"`
}

func Load(onEvent func(FlowEvent), enabled bool) (stop func() error, err error) {
	if !enabled {
		return nil, ErrDisabled
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(flowsObj))
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}
	var obj flowsObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	lnk, err := link.Tracepoint("inet", "inet_sock_set_state", obj.InetSockSetState, nil)
	if err != nil {
		obj.InetSockSetState.Close()
		obj.Events.Close()
		return nil, fmt.Errorf("attach tracepoint: %w", err)
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
