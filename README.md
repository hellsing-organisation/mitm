# mitm — L7 self-audit for your own devices

Kernel-level HTTPS activity auditor: an eBPF flow probe (ground truth: which
process connected where) plus a transparent CA-MITM proxy (full HTTP/1.1 and
HTTP/2 request/response capture), logging everything to JSONL with body files.

**Scope: auditing your own devices and apps.** Not for intercepting anyone
else's traffic.

## What it gives you

- Every outbound TCP-443 flow, with kernel PID/UID/comm attribution
  (`inet_sock_set_state` tracepoint via eBPF)
- Full decrypted L7: method, host, path, headers, request/response bodies
  (gzip/deflate/brotli decoded alongside raw), for HTTP/1.x and HTTP/2
- Per-app attribution on every captured request via 4-tuple correlation
- Tripwire alerts for flows that never reached the proxy (typical: certificate
  pinning — flagged, not decrypted) and for clients rejecting the CA
- QUIC/HTTP3 forced down to TCP (UDP 443 REJECT) so nothing hides there
- Websocket upgrades logged (handshake; frames relayed, not parsed)

## Quickstart (Linux PC)

```sh
make test                       # unit tests, no root needed
make build                      # bpf object + mitmd/mitmctl binaries

sudo ./mitmctl ca gen --key /etc/mitm/ca.key --cert /etc/mitm/ca.crt
# trust /etc/mitm/ca.crt in your browser/system trust store, then:

sudo ./mitmd -config configs/mitm.example.yaml
mitmctl tail -f                 # watch requests stream in
mitmctl query --app telegram --since 2026-10-18T00:00:00Z
```

`mitmd` installs nftables (or iptables) rules at startup: outbound TCP
dports from `ports:` are REDIRECTed to the local proxy; the daemon's own
upstream sockets are excluded via `SO_MARK` (and uid match) so there is no
loop; UDP 443 is rejected to force QUIC fallback. On shutdown everything is
removed.

## Android (rooted)

See `docs/android.md`. `make android` builds static arm64 binaries; the daemon
runs on-device as root with the iptables backend and the CA is installed into
the system store (`mitmctl ca install-android`).

## Config

See `configs/mitm.example.yaml`. Key knobs:

| Key | Meaning |
|---|---|
| `ports` | TCP ports redirected + captured (default `[443]`) |
| `capture.max_body_bytes` | storage cap per body; forwarding is never limited |
| `capture.exclude_content_types` | glob list (default skips images/video/audio/fonts) |
| `filters.exclude_processes` / `include_domains` / `exclude_domains` | capture scoping |
| `redirect.backend` | `auto` (nft → iptables), or force `iptables` on Android |
| `quic.force_tcp` | reject UDP 443 (default true) |

## Output

- `events.jsonl` — one JSON event per line (`flow`, `http`, `alert`, `startup`)
- `bodies/YYYY-MM-DD/<uuid>.{req,res}` — raw captured bodies (truncated at cap)
- `bodies/.../<uuid>.req.decoded` — decoded request body when compressed

## Honest limitations

- **Cert-pinned apps are not decrypted** — they fail the handshake against the
  CA and surface as `client_tls_failed` / `unproxied_tls` alerts. That is the
  intended audit signal.
- **eBPF needs root and a reasonable kernel** (tracepoint since 4.16). Without
  it the daemon runs degraded: full proxy capture, no PID attribution
  (`startup` event carries `bpf_disabled`).
- **DoH** (DNS over HTTPS) is captured as ordinary HTTPS to the DoH resolver.
- iOS is out of scope (no eBPF in XNU).

## Layout

```
bpf/flows.bpf.c        tracepoint probe (ringbuf flow events)
internal/proxy/        transparent MITM proxy (TLS term, ALPN h2/h1, tee, upstream)
internal/audit/        events, store, correlation + tripwire
internal/redirect/     nftables / iptables rule managers
internal/bpf/          loader (build with: make bpf) + degraded stub
cmd/mitmd              daemon
cmd/mitmctl            ca gen/install, redirect on/off/status, tail, query
```
