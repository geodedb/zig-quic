# QUIC System-Level Tuning — Design

**Date:** 2026-04-22
**Status:** Approved for implementation
**Scope:** Cross-repo — `devnw/zig/quic` (source of truth) + `devnw/codepros/geode/geode` (primary consumer)

## Problem

`zig-quic` has no canonical guidance or tooling for the OS-level knobs that bound its throughput on Linux (UDP buffer sizes, qdisc choice, backlog, ephemeral port range). Downstream consumers — `geode` most notably — ship ad-hoc snippets:

- `geode/deployment/scripts/postinstall.sh` sets only `net.core.rmem_max` and `net.core.wmem_max` to 7 MB.
- `geode/deployment/config/geode.conf` + `systemd/geode.service` reference `QUIC_GO_DISABLE_GSO`, a knob from the old `quic-go` transport that `geode` no longer uses — stale and misleading since zig-quic doesn't implement GSO (open issue #109).
- No `fs.file-max`, `udp_mem`, `netdev_max_backlog`, qdisc, or port-range tuning anywhere.
- No revert path, no "only raise, never lower" semantics, no BSD/macOS notes.

Operators deploying geode over zig-quic leave significant throughput on the floor and have no canonical place to look.

## Goals

1. `zig-quic` becomes the source-of-truth for OS tuning guidance.
2. `geode` vendors that guidance and applies it unconditionally on install (package postinstall and `make install`).
3. Tuning is idempotent, "only-raise" at runtime, reversible, and persists across reboots via `/etc/sysctl.d/`.
4. Stale `quic-go` references in geode's deployment surface are purged.

## Non-goals

- Implementing GSO, sendmmsg, or conntrack UDP timeout tuning (out-of-scope — tracked under #109 / #183).
- busy_poll / busy_read (CPU-at-idle tradeoffs not justified by current workload data).
- Elevated `somaxconn` (QUIC is UDP; listen-backlog does not apply to the datapath).
- Runtime auto-detection of kernel / NIC features — static values only.

## The Tuning Set

Ten knobs, chosen for cumulative effect on zig-quic's send/recv path and low operational risk:

| Knob | Value | Rationale |
|---|---|---|
| `net.core.rmem_max` | `7340032` (7 MB) | Ceiling for per-socket `SO_RCVBUF`. Matches the value quic-go documents and that geode already ships; preserved to avoid regression. |
| `net.core.wmem_max` | `7340032` (7 MB) | Ceiling for per-socket `SO_SNDBUF`. Symmetric with `rmem_max`. |
| `net.core.rmem_default` | `2500000` (~2.5 MB) | Default recv buffer when a process does not explicitly `setsockopt`. Raises the floor for zig-quic endpoints that rely on defaults. |
| `net.core.wmem_default` | `2500000` | Symmetric with `rmem_default`. |
| `net.core.netdev_max_backlog` | `5000` | NIC → kernel softirq queue depth. Prevents drops at 10 G+ burst rates without dedicated RX queue tuning. |
| `net.ipv4.udp_mem` | `262144 524288 1048576` | System-wide UDP memory (pages): min / pressure / max. Roughly 1 GB ceiling on 4K-page systems — safe on any box with ≥ 4 GB RAM. |
| `net.ipv4.udp_rmem_min` | `16384` | Per-socket recv-buffer guaranteed floor even under memory pressure. |
| `net.ipv4.udp_wmem_min` | `16384` | Symmetric. |
| `net.ipv4.ip_local_port_range` | `1024 65535` | Ephemeral-port range for client sockets. Important for connection-heavy clients; harmless on servers. |
| `net.core.default_qdisc` | `fq` | Fair-queue qdisc is pacing-aware — gives any future BBR-style CC an honest time base and is a no-op for current zig-quic (which doesn't pace). Loaded via `sch_fq` kernel module (ubiquitous). |
| `fs.file-max` | `1048576` | Kernel-wide fd ceiling. Aligns with geode's existing `LimitNOFILE=65536` service default and leaves headroom for multi-instance hosts. |

### Runtime semantics

- **Only raise, never lower**: `tune-system.sh apply` reads the current kernel value for each `*_max`, `netdev_max_backlog`, and `file-max` knob and writes only if our value is higher. This protects hosts already tuned past our defaults (e.g., 16 MB rmem for 100 G NICs).
- **Persistent**: The drop-in at `/etc/sysctl.d/99-zig-quic.conf` (or `99-geode-quic.conf` for geode) records our values verbatim. Admins who've tuned higher should put their overrides in a file with a higher numeric prefix (e.g., `/etc/sysctl.d/99-local-overrides.conf` loads after `99-zig-quic.conf`).
- **Reversible**: `tune-system.sh revert` removes the drop-in and runs `sysctl --system` to restore to either the pre-existing override or kernel defaults.
- **BSD/macOS**: Documented fallback — `kern.ipc.maxsockbuf=8441037` (≈ 7 MB + 15 % padding), no-op for `fq` / `udp_mem`. No scripted apply on these platforms.

## Components

### zig-quic

```text
docs/
  SYSTEM_TUNING.md                  # per-knob rationale, ranges, verification, BSD/macOS fallback, rollback
config/
  sysctl.d/
    99-zig-quic.conf                # canonical drop-in
scripts/
  tune-system.sh                    # apply | revert | check (idempotent, only-raise)
README.md                           # link to SYSTEM_TUNING.md under "Deployment"
CLAUDE.md                           # one line under "Quick Commands" pointing at the script
```

### geode

```text
deployment/
  sysctl.d/
    99-geode-quic.conf              # superset-identical to zig-quic drop-in
  scripts/
    postinstall.sh                  # extended: all 10 knobs with only-raise, install drop-in
    tune-system.sh                  # vendored from zig-quic, same CLI surface
  systemd/
    geode.service                   # drop stale QUIC_GO_* comment; reference drop-in
  config/
    geode.conf                      # drop stale QUIC_GO_* references in [quic] section
  README.md                         # purge quic-go refs; document full 10-knob set; link upstream
Makefile                            # new install-tuning target; wired into install
```

## Data flow (install-time)

```text
package manager install
  └─> preinstall.sh  (unchanged — create user/group, stop service)
  └─> files laid down — including /etc/sysctl.d/99-geode-quic.conf
  └─> postinstall.sh
        ├─> for each of the 10 knobs: read current, sysctl -w iff higher
        ├─> sysctl --system  (persist check)
        ├─> chown / certs / systemd (unchanged)
        └─> systemctl enable + start

make install  (developer path)
  └─> zig build -Doptimize=ReleaseSafe
  └─> sudo cp zig-out/bin/geode /usr/bin/geode
  └─> $(MAKE) install-tuning   # invokes sudo deployment/scripts/tune-system.sh apply
  └─> sudo systemctl restart geode
```

## Error handling

- `sysctl -w` failures (read-only rootfs, containers without `CAP_NET_ADMIN`, kernel without a knob) are logged and swallowed (`|| true`) — tuning is best-effort, never blocks install.
- Missing `/etc/sysctl.d` (non-systemd / alpine-openrc hosts): skip drop-in; still attempt runtime apply.
- `tune-system.sh` exits non-zero only on its own bugs (bad args), never on individual `sysctl` failures.
- `fq` qdisc unavailable (rare embedded kernels): apply skips and logs one warning.

## Testing

1. **Script unit**: `scripts/tune-system.sh check` on the dev host — verify parse + read-only of current values matches `sysctl -a`.
2. **Idempotency**: run `apply` twice in a row — second run should be a no-op (no writes).
3. **Only-raise**: manually set `rmem_max=16000000`, run `apply`, confirm value unchanged.
4. **Revert**: after `apply`, run `revert`, confirm drop-in removed and `sysctl --system` reloaded.
5. **Geode postinstall**: build a `.deb` via the existing GoReleaser snapshot path and install it in a disposable Docker container; verify `/etc/sysctl.d/99-geode-quic.conf` present and values applied (where the container permits).
6. **No regression**: existing zig-quic tests (`zig build test`) and geode tests (`make test`) pass — this change touches no `.zig` code in either repo.

## Rollout

1. Land in `zig-quic` first (docs + sysctl.d + script). Commit.
2. Land in `geode`. Bump the zig-quic dep pin only if needed (not required for this change — the tuning is packaging, not API).
3. Next `geode` release ships the new postinstall; upgrade path is idempotent (re-applying higher values is a no-op, new values are added).

## Open items rolled into implementation

- Exact text of README "Deployment" section in zig-quic is drafted during implementation.
- Concrete `tune-system.sh` flag names settled during implementation (`apply`, `revert`, `check` subcommands — no flags beyond `--help`).

## Spec self-review

- [x] No placeholders or TBDs.
- [x] Non-goals explicitly name what's excluded.
- [x] Every knob has a one-line rationale tied to zig-quic's datapath.
- [x] "Only raise" vs. "drop-in writes verbatim" tension resolved in the Runtime semantics section.
- [x] Scoped to one cohesive implementation plan (single sprint of work).
