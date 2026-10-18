package audit

import (
	"testing"
	"time"
)

func key1() FlowKey {
	return FlowKey{SrcIP: "10.0.0.5", SrcPort: 44120, DstIP: "93.184.216.34", DstPort: 443}
}

func TestTakeReturnsInfoAndMarksClaimed(t *testing.T) {
	alerts := []Event{}
	r := NewFlowRegistry(func(e Event) { alerts = append(alerts, e) }, []int{443})

	now := time.Now()
	r.Add(key1(), FlowInfo{PID: 123, UID: 1000, Comm: "curl", Ts: now})

	fi := r.Take(key1())
	if fi == nil || fi.PID != 123 || fi.Comm != "curl" {
		t.Fatalf("Take = %+v", fi)
	}

	r.Sweep(now.Add(10 * time.Second))
	if len(alerts) != 0 {
		t.Fatal("claimed flow must not alert")
	}
	fi2 := r.Take(key1())
	if fi2 == nil || fi2.PID != 123 {
		t.Fatal("claimed flow must remain readable during session")
	}
}

func TestSweepAlertsUnclaimedWatched(t *testing.T) {
	alerts := []Event{}
	r := NewFlowRegistry(func(e Event) { alerts = append(alerts, e) }, []int{443})
	pid := int32(456)
	now := time.Now()
	k := key1()
	r.Add(k, FlowInfo{PID: pid, UID: 10200, Comm: "SomeBankApp", Ts: now})

	r.Sweep(now.Add(2 * time.Second))
	if len(alerts) != 0 {
		t.Fatal("alerted too early")
	}
	r.Sweep(now.Add(6 * time.Second))
	if len(alerts) != 1 {
		t.Fatalf("want 1 alert, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Type != TypeAlert || a.Alert == nil || a.Alert.Kind != KindUnproxiedTLS {
		t.Fatalf("bad alert: %+v", a)
	}
	if a.PID == nil || *a.PID != pid || a.Comm != "SomeBankApp" {
		t.Fatalf("attribution lost: %+v", a)
	}

	r.Sweep(now.Add(20 * time.Second))
	if len(alerts) != 1 {
		t.Fatal("alerted twice for same flow")
	}
}

func TestSweepIgnoresUnwatchedPorts(t *testing.T) {
	alerts := []Event{}
	r := NewFlowRegistry(func(e Event) { alerts = append(alerts, e) }, []int{443})
	now := time.Now()
	r.Add(FlowKey{SrcIP: "10.0.0.5", SrcPort: 5, DstIP: "1.1.1.1", DstPort: 853}, FlowInfo{PID: 1, Comm: "x", Ts: now})
	r.Sweep(now.Add(10 * time.Second))
	if len(alerts) != 0 {
		t.Fatal("unwatched port must not alert")
	}
}

func TestReleaseRemoves(t *testing.T) {
	alerts := []Event{}
	r := NewFlowRegistry(func(e Event) { alerts = append(alerts, e) }, []int{443})
	now := time.Now()
	k := key1()
	r.Add(k, FlowInfo{PID: 7, Comm: "c", Ts: now})
	r.Take(k)
	r.Release(k)
	r.Sweep(now.Add(30 * time.Second))
	if len(alerts) != 0 {
		t.Fatal("released flow must not alert")
	}
	if r.Take(k) != nil {
		t.Fatal("released flow must be gone")
	}
}

func TestTakeWaitBlocksForLateFlow(t *testing.T) {
	r := NewFlowRegistry(func(Event) {}, []int{443})
	k := key1()
	go func() {
		time.Sleep(30 * time.Millisecond)
		r.Add(k, FlowInfo{PID: 99, Comm: "late", Ts: time.Now()})
	}()
	fi := r.TakeWait(k, 500*time.Millisecond)
	if fi == nil || fi.PID != 99 {
		t.Fatalf("TakeWait = %+v, want late flow", fi)
	}

	r2 := NewFlowRegistry(func(Event) {}, []int{443})
	if fi := r2.TakeWait(k, 10*time.Millisecond); fi != nil {
		t.Fatalf("TakeWait with no flow should time out, got %+v", fi)
	}
}

func TestMarkClaimedPreventsTripwire(t *testing.T) {
	alerts := []Event{}
	r := NewFlowRegistry(func(e Event) { alerts = append(alerts, e) }, []int{443})
	now := time.Now()
	k := key1()
	r.MarkClaimed(k)
	r.Sweep(now.Add(30 * time.Second))
	if len(alerts) != 0 {
		t.Fatal("tombstone must prevent false tripwire alert")
	}
}

func TestFlowIDStable(t *testing.T) {
	a := FlowID(key1())
	b := FlowID(key1())
	if a != b || len(a) != 16 {
		t.Fatalf("FlowID unstable: %q %q", a, b)
	}
}
