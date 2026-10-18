package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// FlowID derives the stable per-flow identifier shared by flow, http, and
// alert events for the same connection.
func FlowID(k FlowKey) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%+v", k)))
	return hex.EncodeToString(sum[:])[:16]
}

type FlowKey struct {
	SrcIP   string
	SrcPort int
	DstIP   string
	DstPort int
}

type FlowInfo struct {
	PID  int32
	UID  uint32
	Comm string
	Ts   time.Time
}

type flowEntry struct {
	info    FlowInfo
	claimed bool
}

type FlowRegistry struct {
	mu         sync.Mutex
	flows      map[FlowKey]*flowEntry
	onAlert    func(Event)
	watch      map[int]struct{}
	claimedTTL time.Duration
	alertAfter time.Duration
}

const (
	defaultAlertAfter = 5 * time.Second
	defaultClaimedTTL = 10 * time.Minute
)

func NewFlowRegistry(onAlert func(Event), watchedPorts []int) *FlowRegistry {
	w := make(map[int]struct{}, len(watchedPorts))
	for _, p := range watchedPorts {
		w[p] = struct{}{}
	}
	return &FlowRegistry{
		flows:      make(map[FlowKey]*flowEntry),
		onAlert:    onAlert,
		watch:      w,
		claimedTTL: defaultClaimedTTL,
		alertAfter: defaultAlertAfter,
	}
}

func (r *FlowRegistry) Add(key FlowKey, info FlowInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flows[key] = &flowEntry{info: info}
}

func (r *FlowRegistry) Take(key FlowKey) *FlowInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.flows[key]
	if !ok {
		return nil
	}
	e.claimed = true
	fi := e.info
	return &fi
}

// TakeWait polls for a flow that may still be in flight from the BPF ringbuf
// (kernel event → userspace latency can exceed the local TLS handshake).
func (r *FlowRegistry) TakeWait(key FlowKey, timeout time.Duration) *FlowInfo {
	deadline := time.Now().Add(timeout)
	for {
		if fi := r.Take(key); fi != nil {
			return fi
		}
		if !time.Now().Before(deadline) {
			return nil
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// MarkClaimed inserts a claimed tombstone so the tripwire does not fire for a
// session the proxy handled when no BPF flow event ever arrived (degraded or
// slower than the TakeWait window).
func (r *FlowRegistry) MarkClaimed(key FlowKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.flows[key]; !ok {
		r.flows[key] = &flowEntry{claimed: true}
	}
}

func (r *FlowRegistry) Release(key FlowKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.flows, key)
}

func (r *FlowRegistry) Sweep(now time.Time) {
	r.mu.Lock()
	var fired []Event
	for k, e := range r.flows {
		age := now.Sub(e.info.Ts)
		if e.claimed {
			if age > r.claimedTTL {
				delete(r.flows, k)
			}
			continue
		}
		if _, watched := r.watch[k.DstPort]; !watched {
			continue
		}
		if age > r.alertAfter {
			pid := e.info.PID
			uid := e.info.UID
			fired = append(fired, Event{
				Ts:   now,
				Type: TypeAlert,
				PID:  &pid,
				UID:  &uid,
				Comm: e.info.Comm,
				Src:  joinHostPort(k.SrcIP, k.SrcPort),
				Dst:  joinHostPort(k.DstIP, k.DstPort),
				Alert: &AlertDetail{
					Kind: KindUnproxiedTLS,
					Note: "no proxy session within window (likely cert pinning or non-TLS on watched port)",
				},
			})
			delete(r.flows, k)
		}
	}
	r.mu.Unlock()
	for _, e := range fired {
		if r.onAlert != nil {
			r.onAlert(e)
		}
	}
}

func joinHostPort(ip string, port int) string {
	return net.JoinHostPort(ip, strconv.Itoa(port))
}
