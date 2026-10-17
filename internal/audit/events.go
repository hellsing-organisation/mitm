package audit

import "time"

const (
	KindUnproxiedTLS    = "unproxied_tls"
	KindClientTLSFailed = "client_tls_failed"
	KindStoreDegraded   = "store_degraded"
	KindBPFDisabled     = "bpf_disabled"
	KindRingbufOverflow = "ringbuf_overflow"
)

const (
	TypeFlow    = "flow"
	TypeHTTP    = "http"
	TypeAlert   = "alert"
	TypeStartup = "startup"
)

type HTTPDetail struct {
	Method       string            `json:"method"`
	Host         string            `json:"host"`
	Path         string            `json:"path"`
	Status       int               `json:"status"`
	ReqHeaders   map[string]string `json:"req_headers,omitempty"`
	ResHeaders   map[string]string `json:"res_headers,omitempty"`
	ReqBody      string            `json:"req_body,omitempty"`
	ResBody      string            `json:"res_body,omitempty"`
	ReqBodyBytes int64             `json:"req_body_bytes,omitempty"`
	ResBodyBytes int64             `json:"res_body_bytes,omitempty"`
	Truncated    bool              `json:"truncated,omitempty"`
	Err          string            `json:"err,omitempty"`
	Note         string            `json:"note,omitempty"`
}

type AlertDetail struct {
	Kind string `json:"kind"`
	Note string `json:"note,omitempty"`
}

type Event struct {
	Ts     time.Time    `json:"ts"`
	Type   string       `json:"type"`
	FlowID string       `json:"flow_id,omitempty"`
	PID    *int32       `json:"pid,omitempty"`
	UID    *uint32      `json:"uid,omitempty"`
	Comm   string       `json:"comm,omitempty"`
	Src    string       `json:"src,omitempty"`
	Dst    string       `json:"dst,omitempty"`
	SNI    string       `json:"sni,omitempty"`
	Proto  string       `json:"proto,omitempty"`
	HTTP   *HTTPDetail  `json:"http,omitempty"`
	Alert  *AlertDetail `json:"alert,omitempty"`
}
