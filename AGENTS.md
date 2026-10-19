# AGENTS.md

Transparent CA-MITM HTTPS capture proxy + eBPF flow attribution (`inet_sock_set_state`
tracepoint) for auditing L7 activity of one's own devices. Go 1.26 + cilium/ebpf;
eBPF side in C. Spec: `docs/superpowers/specs/2026-10-18-l7-audit-design.md`
(includes post-verification kernel 6.18 findings — read before touching
`bpf/flows.bpf.c` or the loader). Plan: `docs/superpowers/plans/2026-10-18-l7-audit.md`
(fully implemented). History: `CHANGELOG.md`.

## Commands

- `make test` — unit tests, no root, must always pass
- `make build` — compiles `internal/bpf/flows.bpf.o` (needs clang) and builds
  `mitmd` (with `-tags bpf`) + `mitmctl` into the repo root
- `make bpf` — recompile object + verify tagged build/tests
- `make android` — static arm64 binaries into `dist/`
- `sudo make demo` — root end-to-end: nftables redirect, curl example.com,
  assert captured event, teardown

## Critical knowledge

- Without `-tags bpf`, `internal/bpf` builds a stub and mitmd runs degraded
  (proxy-only, no PID attribution). The embedded `flows.bpf.o` is gitignored
  and machine-generated — `make build` recreates it.
- The BPF probe is layout-agnostic by design: tracepoint group discovery
  (`sock` vs `inet`) and record offsets are parsed from the live tracefs
  `format` file and injected via the `cfg` ARRAY map. Do not hardcode offsets.
- cilium/ebpf `VariableSpec.Set` does NOT mutate the loaded `.rodata`; use the
  array-map pattern. Tracepoint fields must be read at their exact format-file
  widths (`protocol` is `__u16`).
- `sport` is unbound at `TCP_SYN_SENT` — flow events complete on the first
  post-SYN transition (see design doc implementation notes).
- Root runs (sudo demo) can leave root-owned `internal/bpf/flows.bpf.o`; the
  owning user can `rm -f` it (directory is user-owned).
- After a hard kill (`kill -9`) of mitmd, nftables table `mitm_audit` lingers
  and blackholes TCP 443 — clean with `make teardown` (or
  `sudo nft delete table inet mitm_audit`).
- Repo path/module spell the org `hellsing-organization`, but the GitHub org
  is `hellsing-organisation` — known mismatch, don't "fix" one side blindly.

## Conventions

- No code comments unless explicitly requested.
- Tests use stdlib `testing` only; eBPF-dependent tests go behind
  `-tags integration` and must skip gracefully.
- Commit messages: `feat(scope):`, `fix(scope):`, `docs:`, `build(scope):`.
