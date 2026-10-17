#!/bin/bash
# Builds and deploys mitmd/mitmctl to a rooted Android device over adb.
# Usage: scripts/android-run.sh [serial] [--deploy-only]
set -euo pipefail

ADB_SERIAL="${1:-}"
ADB="adb"
if [ -n "$ADB_SERIAL" ] && [ "$ADB_SERIAL" != "--deploy-only" ]; then
    ADB="adb -s $ADB_SERIAL"
fi

make android

$ADB push dist/mitmd-linux-arm64 /data/local/tmp/mitmd
$ADB push dist/mitmctl-linux-arm64 /data/local/tmp/mitmctl
$ADB shell "chmod 755 /data/local/tmp/mitmd /data/local/tmp/mitmctl"

if [ "${1:-}" = "--deploy-only" ] || [ "${2:-}" = "--deploy-only" ]; then
    echo "deployed. next: adb shell, then:"
    echo "  /data/local/tmp/mitmctl ca gen --key /data/local/tmp/mitm/ca.key --cert /data/local/tmp/mitm/ca.crt"
    echo "  scripts/install-android-ca.sh /data/local/tmp/mitm/ca.crt"
    exit 0
fi

echo "starting mitmd on device"
$ADB shell "su -c 'mkdir -p /data/local/tmp/mitm && cd /data/local/tmp/mitm && nohup /data/local/tmp/mitmd -config /data/local/tmp/mitm/mitm.yaml > mitmd.log 2>&1 &'"
echo "logs: adb shell su -c 'tail /data/local/tmp/mitm/mitmd.log'"
echo "events: /data/local/tmp/mitm-audit/events.jsonl (or per config output dir)"
