# L7 Self-Audit: eBPF Ground Truth + CA MITM Proxy ("mitm")

**Date:** 2026-10-18
**Status:** Approved (Approach A), user delegated detailed decisions
**Owner:** hellsing-organization

## Purpose

Audit all L7 (HTTP/HTTPS) internet activity **of our own devices and apps** so we
know exactly which processes/apps send what data to which servers. Targets:

- Linux PCs (root or sudo-capable, modern kernel)
- Rooted Android phones (on-device daemon, per-app/UID attribution)

Not in scope: iOS (XNU has no eBPF; different project), third-party devices.

## Non-negotiable technical realities (design constraints)

1. **eBPF cannot decrypt TLS.** Plaintext is captured either (a) at the TLS
   library boundary via uprobes, or (b) by a MITM proxy with a locally-trusted
   CA. We chose (b) for content, (a) is out of scope for v1.
2. **Transparent redirect** (nftables/iptables NAT REDIRECT) is the only
   interception that catches every TCP app with zero per-app configuration.
3. **Cert-pinned apps will fail the TLS handshake** against our CA. Their flows
   still appear in the kernel-level flow log (destination, SNI from flow
   correlation where possible) flagged `pinning-suspect`. This is a feature:
   it's an honest audit signal, not data loss hiding as silence.
4. **QUIC/HTTP3 (UDP 443) cannot be MITM'd** by a TCP proxy. We REJECT UDP 443
   so apps fall back to TCP TLS, which we capture. DoH (DNS-over-HTTPS) is
   captured as ordinary HTTPS traffic to the DoH resolver.
5. **Go static binaries and browser-internal TLS bypass shared-lib hooks**;
   with the CA + transparent redirect approach they are covered like everything
   else (except pinned ones). This is why Approach A was chosen.

## Architecture (Approach A: transparent intercept + eBPF ground truth)

```
 app (pid/uid) ──TCP 443──► [nftables/iptables REDIRECT] ──► mitmd listener (127.0.0.1:8080)
                                    │                            │  SO_ORIGINAL_DST ──► real dst:443
                                    │                            │  dynamic leaf cert (CA-signed, per-SNI)
   [BPF: kprobe tcp_v{4,6}_connect]│                            │  TLS ALPN: h2 / http/1.1
        ringbuf flow events ────┐  │                            ▼
                                │  │                     upstream dial (fwmark/uid-excluded)
                                ▼  ▼                     (TLS verify against system roots)
                          correlate by 4-tuple ──► JSONL events + body files
                                                    (+ tripwire: flows with no proxy session)
   [UDP 443 REJECT rule] ← force QUIC fallback
```

### Components

| Component | Tech | Responsibility |
|---|---|---|
| `mitmd` daemon | Go + cilium/ebpf | Load BPF, consume ring buffer, run proxy, correlate, write events |
| Transparent MITM proxy | Go stdlib TLS + x/net/http2 | Terminate client TLS (minted leaf certs), parse HTTP/1+h2, re-originated upstream, tee bodies |
| `bpf/flows.bpf.c` | C CO-RE (vmlinux.h) | kprobe `tcp_v4_connect`/`tcp_v6_connect` → ringbuf {cookie,pid,uid,comm,4-tuple} |
| Redirect layer | nftables (PC) / iptables (Android) | TCP dport {443,...} REDIRECT→8080, UDP 443 REJECT, exclude daemon traffic (owner-uid/mark) |
| Correlator | Go userspace | join flow events ↔ proxy sessions by 4-tuple; flag unproxied flows |
| Store | filesystem | `events.jsonl` + `bodies/YYYY-MM-DD/<uuid>.{req,res}[.decoded]` |
| `mitmctl` CLI | Go | `ca gen`, `redirect on/off/status`, `tail`, `query`, `ca install-android` |

### Correlation & attribution

- BPF connect probe emits the client socket's local port at connect time.
- Proxy accepted-conn: `getpeername()` = client ip:port (same tuple),
  `SO_ORIGINAL_DST`/`IP6T_SO_ORIGINAL_DST` = original destination.
- Join key: exact 4-tuple. `flow_id = sha256(tuple + connect_ts)` shared by
  both event types → each HTTP event carries pid/comm/uid even though the proxy
  never sees the process.
- Tripwire: any flow event (dport in capture set) without a matching proxy
  session within 5s → `alert{kind=unproxied_tls}` (typically cert pinning or
  non-TLS garbage on 443).
- Degraded mode: if BPF load fails (old Android kernel), daemon runs
  proxy-only, events carry `pid=null`, warning event emitted at startup.

### Proxy details

- **Leaf certs:** in-memory LRU (4096) minted per-SNI, ECDSA P-256, 1y expiry,
  signed by CA. No SNI (raw IP) → SAN=IP mint.
- **ALPN:** advertise `h2,http/1.1`; serve h2 via x/net/http2 `ServeConn`.
- **Upstream:** `http.Transport` with per-request `DialTLSContext`: dial the
  **original dst** (pool key), TLS `ServerName` = client's SNI from request
  context, ALPN offered = client's negotiated proto. **Upstream certs are
  verified against system roots** — we audit, we do not weaken our own outbound
  trust.
- **Bodies:** stream upstream/downstream untouched; tee into capped writers
  (config `max_body_bytes`, hard cap 16 MiB default) → raw body file; decode
  `Content-Encoding` (gzip, deflate, br via andybalholm/brotli) → `.decoded`
  alongside. Capture decisions from config (`content_types`,
  include/exclude `domains` globs, `processes`). Forwarding is never affected
  by capture limits — only storage truncates.
- **WebSockets:** log handshake + upgrade headers; raw pipes afterwards (v1
  does not parse frames).
- **Loop prevention:** daemon's own sockets carry `SO_MARK=1337`
  (`unix.SetsockoptInt`) AND redirect rules exclude daemon uid; both belts.

### Config (YAML)

```yaml
listen: 127.0.0.1:8080
ports: [443, 8443]                 # ports redirected/captured
ca:  { key: /etc/mitm/ca.key, cert: /etc/mitm/ca.crt }
redirect: { mark: 1337, use: auto } # auto: nft on PC, iptables on android
quic: { force_tcp: true }
capture:
  bodies: true
  max_body_bytes: 16777216
  content_types: ["*/*"]            # or list; "*/*" minus exclude list
  exclude_content_types: ["image/*", "video/*", "audio/*", "font/*"]
filters:
  exclude_processes: ["mitmd"]
  include_domains: []               # glob; empty = all
  exclude_domains: []
output:
  dir: /var/log/mitm-audit
  jsonl: events.jsonl
```

### Event schema (JSONL, one per line)

```json
{"ts":"2026-10-18T01:02:03Z","type":"flow","flow_id":"…","pid":123,"uid":1000,
 "comm":"curl","src":"10.0.0.5:44120","dst":"104.18.0.1:443","dport":443}
{"ts":"…","type":"http","flow_id":"…","pid":123,"comm":"curl",
 "sni":"api.example.com","proto":"h2",
 "http":{"method":"POST","host":"api.example.com","path":"/v1/telemetry",
 "status":200,"req_headers":{…},"res_headers":{…},
 "req_body":"bodies/2026-10-18/8f….req","req_body_bytes":1834,
 "res_body":"bodies/2026-10-18/8f….res","res_body_bytes":512,
 "truncated":false}}
{"ts":"…","type":"alert","alert":{"kind":"unproxied_tls","flow_id":"…","pid":456,
 "comm":"SomeBankApp","dst":"1.2.3.4:443","note":"likely cert pinning"}}
```

### Android deployment

- Build: `CGO_ENABLED=0 GOOS=linux GOARCH=arm64` static binary (runs on Android
  kernel via adb/root shell; NDK/GOOS=android fallback documented if needed).
- iptables (root): `-t nat -A OUTPUT -p tcp ! --uid-owner <mitmd_uid>
  --dport 443 -j REDIRECT --to-port 8080`; `REJECT` UDP 443; same for ip6tables.
- CA: with root, install into `/system/etc/security/cacerts/` (and Android 14+
  APEX conscrypt store) via `mitmctl ca install-android` — remounts /system
  rw temporarily, writes `<hash>.0`, documents both layouts.
- Daemon as a `nohup`/`init.d` service under its own uid; logdir
  `/data/local/tmp/mitm-audit`.

### Error handling

- BPF load failure → degraded mode (proxy-only) + startup warning event.
- Upstream connect/TLS failure → `http` event with `status:0`,
  `error:"…"` (this is how pinning-suspects also surface on the proxy side).
- Store disk full → drop bodies (metadata only), keep events, emit
  `alert{kind=store_degraded}` once.
- Ring buffer overflow → counter event, continue (never block kernel path).

## Testing

- **Unit (CI, no root):** config parse/validate; CA/leaf minting + real TLS
  handshake; 4-tuple correlator (happy, unmatched→alert, reorder); store
  writer (JSONL validity, truncation marks, encoding decode); proxy end-to-end
  against `httptest.NewTLSServer` through the transparent path with a stub
  original-dst resolver; filters (domain/process/content-type glob matrix).
- **Build:** `make bpf` (clang compile, `bpf2go` generate) in CI with clang;
  BPF attach tests behind `-tags integration`, skip when not root.
- **Manual e2e:** `make demo` (root): starts daemon, installs rules, curls
  https://example.com, asserts event in JSONL, tears down. Android e2e
  documented in `docs/android.md`.

## Phasing

- **v1 (this spec):** everything above.
- **v2 candidates:** uprobe SSL_read/SSL_write capture for pinned apps
  (plaintext without CA), DNS↔IP mapping from eBPF, WebSocket frame logging,
  QUIC keylog-based decryption, per-UID dashboards, flow byte counters.
- **Rejected for v1:** browser offset scanning (covered by CA), Go-binary
  hooking (covered by CA), SQLite store (JSONL is greppable; revisit at scale).

## Explicitly out of scope

- Intercepting traffic of devices/users other than the owner's own.
- Bypassing certificate pinning (flows get flagged, not decrypted).
