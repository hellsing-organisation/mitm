# Android deployment (rooted devices)

## Requirements

- Rooted Android phone, unlocked bootloader
- Kernel that allows eBPF tracepoint attach: Android ships BPF since kernel 4.9,
  but tracepoint attach via perf_event needs a permissive SELinux context and
  kernel config. Kernel >= 5.4 recommended. If loading fails, `mitmd` logs
  `bpf_disabled` and runs degraded (proxy-only, no PID attribution).
- Static binaries built from the PC: `make android` → `dist/*-linux-arm64`

Android apps that pin certificates will fail TLS against the MITM CA — those
flows show up as `client_tls_failed` alerts and `unproxied_tls` tripwire events
with destination info, by design.

## 1. Build and push

```sh
make android
adb push dist/mitmd-linux-arm64 /data/local/tmp/mitmd
adb push dist/mitmctl-linux-arm64 /data/local/tmp/mitmctl
adb shell "chmod 755 /data/local/tmp/mitmd /data/local/tmp/mitmctl"
```

## 2. Generate CA and install into system store

```sh
adb shell
su
cd /data/local/tmp
./mitmctl ca gen --key mitm/ca.key --cert mitm/ca.crt
sh /path/to/scripts/install-android-ca.sh mitm/ca.crt   # run from repo copy pushed to device
reboot
```

The installer writes `/system/etc/security/cacerts/<hash>.0` and, on Android 14+,
attempts `/apex/com.android.conscrypt/cacerts/` (read-only on many builds; see
script warnings and the Magisk system-CA module alternative).

## 3. Config and run

Minimal `/data/local/tmp/mitm/mitm.yaml`:

```yaml
listen: 127.0.0.1:8080
ports: [443]
ca: { key: /data/local/tmp/mitm/ca.key, cert: /data/local/tmp/mitm/ca.crt }
redirect: { mark: 1337, managed: true, backend: iptables }
quic: { force_tcp: true }
output: { dir: /data/local/tmp/mitm-audit, jsonl: events.jsonl }
```

Run as root (needed for iptables + BPF):

```sh
su
nohup /data/local/tmp/mitmd -config /data/local/tmp/mitm/mitm.yaml \
    > /data/local/tmp/mitm/mitmd.log 2>&1 &
```

## 4. Pull the audit trail

```sh
adb pull /data/local/tmp/mitm-audit .
./mitmctl tail --file mitm-audit/events.jsonl -f
```

## Notes

- iptables backend is auto-selected on Android (nftables is uncommon there).
- Per-app attribution uses kernel PID/UID; package names can be mapped from UID
  via `pm list packages -U` on the device.
- If the device uses MPTCP/exotic kernels the `inet_sock_set_state` tracepoint
  still works (stable since 4.16) but `family` sanity-check failures mean the
  vendor changed the layout — report it, the struct is in `bpf/flows.bpf.c`.
