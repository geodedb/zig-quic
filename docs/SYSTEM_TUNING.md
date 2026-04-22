# System Tuning for zig-quic

Source-of-truth for OS-level knobs that bound zig-quic throughput on Linux. Downstream consumers (e.g. `geode`) vendor the same values and helper script.

## TL;DR

```bash
scripts/tune-system.sh check              # current vs. recommended
sudo scripts/tune-system.sh apply         # raise + persist
sudo scripts/tune-system.sh revert        # undo
```

## What `apply` does

1. For each knob in `config/sysctl.d/99-zig-quic.conf`:
   - Numeric knob with `current < recommended` → raise via `sysctl -w`.
   - Numeric knob with `current >= recommended` → leave untouched.
   - Multi-value / non-numeric (`udp_mem`, `ip_local_port_range`, `default_qdisc`) → write verbatim.
2. Install `/etc/sysctl.d/99-zig-quic.conf` for persistence across reboots.
3. Run `sysctl --system` to reload drop-ins in precedence order.

Individual `sysctl -w` failures (read-only rootfs, no `CAP_NET_ADMIN`, kernel missing a knob) are logged and swallowed — tuning is best-effort and never blocks an install.

## The knobs

| Knob | Value | Why |
|---|---|---|
| `net.core.rmem_max` | 7340032 (7 MB) | Per-socket `SO_RCVBUF` ceiling. Matches quic-go's recommendation. |
| `net.core.wmem_max` | 7340032 (7 MB) | Per-socket `SO_SNDBUF` ceiling. |
| `net.core.rmem_default` | 2500000 | Default recv buffer when a process does not `setsockopt`. |
| `net.core.wmem_default` | 2500000 | Symmetric. |
| `net.core.netdev_max_backlog` | 5000 | NIC → softirq queue depth. Prevents drops at 10 G+ bursts. |
| `net.ipv4.udp_mem` | `262144 524288 1048576` | System-wide UDP memory pages (min / pressure / max). |
| `net.ipv4.udp_rmem_min` | 16384 | Per-socket recv floor under memory pressure. |
| `net.ipv4.udp_wmem_min` | 16384 | Symmetric. |
| `net.ipv4.ip_local_port_range` | `1024 65535` | Ephemeral port range for clients. |
| `net.core.default_qdisc` | `fq` | Pacing-aware qdisc; requires `sch_fq` module (ubiquitous). |
| `fs.file-max` | 1048576 | Kernel-wide fd ceiling; aligns with `LimitNOFILE=65536`. |

## Precedence and local overrides

`/etc/sysctl.d/` files load in lexical order. For higher local values, use a later-sorting filename (e.g. `99-zzz-local.conf`). Our drop-in never touches files it did not write.

## Verifying

```bash
sysctl net.core.rmem_max net.core.wmem_max net.core.default_qdisc
# net.core.rmem_max = 7340032
# net.core.wmem_max = 7340032
# net.core.default_qdisc = fq
```

After reboot, re-run `scripts/tune-system.sh check`.

## Containers

```bash
docker run \
  --sysctl net.core.rmem_max=7340032 \
  --sysctl net.core.wmem_max=7340032 \
  --sysctl net.core.rmem_default=2500000 \
  --sysctl net.core.wmem_default=2500000 \
  <image>
```

Unprivileged containers without `CAP_NET_ADMIN` cannot set sysctls at runtime — tune the host instead and let the container inherit.

## BSD / macOS

No automated apply. Manual equivalent:

```bash
sudo sysctl -w kern.ipc.maxsockbuf=8441037   # ~7 MB + 15% padding
```

Persistence: FreeBSD `/etc/sysctl.conf`; macOS via LaunchDaemon. `fq`, `udp_mem`, `ip_local_port_range` have no direct BSD equivalents.

## Deliberately not tuned

- `net.core.busy_poll` / `busy_read` — CPU-at-idle tradeoff not justified by current workload data.
- `somaxconn` — QUIC is UDP; listen-backlog does not apply to the datapath.
- Conntrack UDP timeouts — only matters behind stateful NAT; tune per-deployment.
- GSO / GRO — zig-quic does not currently use GSO (tracked under issue #109). No knob is meaningful today.

## Spec

`docs/superpowers/specs/2026-04-22-quic-system-tuning-design.md`
