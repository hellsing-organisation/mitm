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

go build -buildvcs=false -o "$DIR/mitmd" "$ROOT/cmd/mitmd"

cat > "$DIR/mitm.yaml" <<EOF
listen: 127.0.0.1:${PORT}
ports: [443]
ca: { key: ${DIR}/ca.key, cert: ${DIR}/ca.crt }
redirect: { mark: 1337, managed: true, backend: nft }
quic: { force_tcp: true }
output: { dir: ${DIR}/audit, jsonl: events.jsonl }
EOF

"$DIR/mitmd" -config "$DIR/mitm.yaml" &
MITMD_PID=$!
for i in $(seq 1 50); do [ -f "$DIR/audit/proxy.addr" ] && break; sleep 0.1; done

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
    echo "DEMO INCOMPLETE: no http event (bpf degraded? nft missing? check $(dirname "$0")/demo output)"
fi
