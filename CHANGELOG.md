# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-10-19

First working release. Transparent CA-MITM HTTPS capture proxy + eBPF flow
attribution for auditing L7 activity of one's own devices.

### Added

- `mitmd` daemon: nftables/iptables transparent redirect of outbound TCP
  (default port 443), local MITM proxy with per-SNI CA-signed leaf certs,
  HTTP/1.1 and HTTP/2 (ALPN) support, WebSocket upgrade relay, streaming
  flush, gzip/deflate/brotli body decoding alongside raw capture
- eBPF flow probe (`inet_sock_set_state` tracepoint): kernel PID/UID/comm
  attribution, joined to proxied sessions by 4-tuple with shared `flow_id`
- Tripwire alerts: `unproxied_tls` (likely cert pinning), `client_tls_failed`
  (CA rejected / 0-RTT early data), `bpf_disabled`, `store_degraded`
- QUIC/HTTP3 forced down to TCP (UDP 443 REJECT) so nothing hides from capture
- JSONL event stream (`flow|http|alert|startup`) + body-file store with
  size-capped capture; forwarding is never limited by capture caps
- YAML config with domain/process/content-type filters
  (`configs/mitm.example.yaml`)
- `mitmctl` CLI: `ca gen`, `ca install-android`, `redirect on/off/status`,
  `tail [-f]`, `query` (app/domain/method/status/since/limit)
- Android: static arm64 builds (`make android`), system CA installer script,
  deployment guide (`docs/android.md`), iptables backend with uid/mark loop
  prevention
- Self-diagnosing startup: BPF self-test with per-stage counters (calls/syn/
  emit/rb_fail) and discovered tracepoint group/offsets recorded in the
  startup event
- End-to-end demo (`make demo`, root): installs scoped nftables rules, curls
  example.com, asserts a captured L7 event, tears everything down

### Kernel compatibility notes

Verified on Linux 6.18 (Manjaro). The probe handles kernel drift at load
time rather than compile time:

- Tracepoint group discovery: `sock/inet_sock_set_state` (6.18+) with
  fallback to `inet/inet_sock_set_state` (pre-6.18 layout, skbaddr present)
- Record field offsets parsed from the live tracefs `format` file and
  injected via an ARRAY map; no `.rodata` rewriting, no hardcoded layouts
- Flow events emitted on the first post-SYN_SENT transition because the
  ephemeral source port is not yet bound at SYN_SENT

### Known limitations

- Certificate-pinned apps are flagged (`client_tls_failed` /
  `unproxied_tls`), not decrypted — by design for self-audit
- TLS 1.3 0-RTT clients cannot be intercepted (early data is encrypted to
  the real server); flagged as failures
- DNS over HTTPS is captured as ordinary HTTPS to the resolver
- `go` binaries that pin the system proxy or exotic MPTCP paths are not
  special-cased; they flow through the transparent redirect like everything
  else
- iOS is out of scope (XNU has no eBPF)
