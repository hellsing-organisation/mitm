package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteEventRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir, "e.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ts := time.Now().UTC().Truncate(time.Millisecond)
	pid := int32(4242)
	uid := uint32(1000)
	ev := Event{
		Ts:     ts,
		Type:   "http",
		FlowID: "flow-1",
		PID:    &pid,
		UID:    &uid,
		Comm:   "curl",
		Src:    "10.0.0.5:44120",
		Dst:    "93.184.216.34:443",
		SNI:    "example.com",
		Proto:  "http/1.1",
		HTTP: &HTTPDetail{
			Method:       "POST",
			Host:         "example.com",
			Path:         "/v1/telemetry",
			Status:       200,
			ReqHeaders:   map[string]string{"content-type": "application/json"},
			ResHeaders:   map[string]string{"content-type": "application/json"},
			ReqBody:      "bodies/x.req",
			ResBody:      "bodies/x.res",
			ReqBodyBytes: 1834,
			ResBodyBytes: 512,
		},
	}
	if err := s.WriteEvent(ev); err != nil {
		t.Fatal(err)
	}
	flowEv := Event{Ts: ts, Type: "flow", FlowID: "flow-2"}
	if err := s.WriteEvent(flowEv); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d", len(lines))
	}
	var got Event
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("line not valid json: %v", err)
	}
	if got.HTTP == nil || got.HTTP.Method != "POST" || got.HTTP.Status != 200 {
		t.Fatalf("http detail lost: %+v", got.HTTP)
	}
	if got.PID == nil || *got.PID != 4242 || got.UID == nil || *got.UID != 1000 {
		t.Fatalf("pid/uid lost: %+v", got)
	}
	if got.SNI != "example.com" || got.Proto != "http/1.1" {
		t.Fatalf("sni/proto lost: %+v", got)
	}

	var gotFlow Event
	if err := json.Unmarshal([]byte(lines[1]), &gotFlow); err != nil {
		t.Fatal(err)
	}
	if gotFlow.PID != nil || gotFlow.HTTP != nil {
		t.Fatalf("omitempty failed: %+v", gotFlow)
	}
}

func TestSaveBody(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir, "e.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	rel, err := s.SaveBody("req", []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rel, filepath.Join("bodies", time.Now().UTC().Format("2006-01-02"))) {
		t.Fatalf("rel path missing day dir: %q", rel)
	}
	if !strings.HasSuffix(rel, ".req") {
		t.Fatalf("rel path missing kind suffix: %q", rel)
	}
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello world" {
		t.Fatalf("body content mismatch: %q", b)
	}

	rel2, err := s.SaveBody("req", []byte("other"))
	if err != nil {
		t.Fatal(err)
	}
	if rel2 == rel {
		t.Fatal("uuid collision or reused path")
	}
}
