#!/bin/bash
# End-to-end demo: starts mitmd with nftables redirect, curls an HTTPS site,
# verifies the event landed in the JSONL, then tears everything down.
# Must run as root on a Linux PC. Uses a self-contained config in /tmp.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root: sudo make demo" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$(mktemp -d /tmp/mitm-demo.XXXXXX)"
PORT=18080
cleanup() {
    [ -n "${MITMD_PID:-}" ] && kill "$MITMD_PID" 2>/dev/null || true
    wait "${MITMD_PID:-}" 2>/dev/null || true
    nft delete table inet mitm_audit 2>/dev/null || true
    rm -rf "$DIR"
}
trap cleanup EXIT

go build -buildvcs=false -o "$DIR/mitmd" "$ROOT/cmd/mitmd" || exit 1

# Build with eBPF flow attribution when clang + kernel BTF are available.
if command -v clang >/dev/null 2>&1 && [ -f /sys/kernel/btf/vmlinux ]; then
    if clang -target bpfel -O2 -g -I"$ROOT/bpf" -c "$ROOT/bpf/flows.bpf.c" \
        -o "$ROOT/internal/bpf/flows.bpf.o" 2>/dev/null; then
        go build -buildvcs=false -tags bpf -o "$DIR/mitmd" "$ROOT/cmd/mitmd"
        echo "mitmd built with eBPF flow probe"
    else
        echo "WARNING: bpf probe failed to compile; running degraded (no PID attribution)"
    fi
else
    echo "WARNING: clang or /sys/kernel/btf/vmlinux missing; running degraded (no PID attribution)"
fi

cat > "$DIR/mitm.yaml" <<EOF
listen: 127.0.0.1:${PORT}
ports: [443]
ca: { key: ${DIR}/ca.key, cert: ${DIR}/ca.crt }
redirect: { mark: 1337, managed: true, backend: nft }
quic: { force_tcp: true }
output: { dir: ${DIR}/audit, jsonl: events.jsonl }
EOF

"$DIR/mitmd" -config "$DIR/mitm.yaml" > "$DIR/mitmd.log" 2>&1 &
MITMD_PID=$!
for i in $(seq 1 50); do [ -f "$DIR/audit/proxy.addr" ] && break; sleep 0.1; done
if [ ! -f "$DIR/audit/proxy.addr" ]; then
    echo "DEMO FAILED: mitmd did not start. Log:" >&2
    cat "$DIR/mitmd.log" >&2
    exit 1
fi

# Trust our CA for the outbound client.
# curl is excluded from capture only via filters (none here), so the request
# should appear in events.jsonl with pid/comm attribution from the BPF probe.
echo "curling example.com through transparent intercept..."
curl -sS --cacert "$DIR/ca.crt" https://example.com/ -o /dev/null || true

sleep 1
echo "--- events ---"
cat "$DIR/audit/events.jsonl" || true
if grep -q '"type":"http"' "$DIR/audit/events.jsonl" 2>/dev/null; then
    echo "DEMO OK: L7 event captured"
else
    echo "DEMO INCOMPLETE: no http event captured"
    echo "--- mitmd log (tail) ---"
    tail -20 "$DIR/mitmd.log" || true
    exit 1
fi
