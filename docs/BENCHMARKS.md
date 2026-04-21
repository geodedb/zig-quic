# Benchmarks Operator Manual

Quick-reference guide for running the v2 benchmark suite, interpreting
its output, and extending it with new scenarios.

Companion documents:

- Targets + absolute gates: [`docs/PERFORMANCE_TARGETS.md`](PERFORMANCE_TARGETS.md)
- A/B protocol + decision log: [`docs/PERFORMANCE_TRACKING.md`](PERFORMANCE_TRACKING.md)
- Gate script: [`scripts/perf-gate.sh`](../scripts/perf-gate.sh)

## Quick Start

```bash
# Full suite — micro + integration (external skipped unless toolchains present)
zig build bench -- --suite=all --output=/tmp/run.json

# One tier (shortcut steps)
zig build bench-micro           # alias for --suite=micro
zig build bench-integration     # alias for --suite=integration
zig build bench-external        # alias for --suite=external

# Equivalent via flag:
zig build bench -- --suite=micro
zig build bench -- --suite=integration
zig build bench -- --suite=external

# One scenario
zig build bench -- --suite=micro/varint
zig build bench -- --suite=integration/handshake_e2e
zig build bench -- --suite=integration/flush_cadence

# Discover what's available
zig build bench -- --list

# Regression gate against stored baseline
scripts/perf-gate.sh --baseline=benchmarks/results/baseline.json \
                     --current=/tmp/run.json

# Regression gate in paired-commit mode (auto worktree + capture)
scripts/perf-gate.sh --baseline-commit=<parent-sha>

# Refresh the stored baseline (only after a sanctioned revision)
zig build bench -- --suite=all --output=benchmarks/results/baseline.json
```

Output JSON is a `ResultDocument` (see `benchmarks/common.zig`). Each
row carries the scenario name, variant, iterations, wall / cpu times,
p50 / p95 / p99 latencies, stddev, allocation bytes, and — for external
rows — the implementation name.

## Per-Suite Detail

Typical runtimes below are wall-clock on an x86_64 Linux workstation
with the `performance` governor; numbers on your hardware will vary
with CPU and load.

### Micro tier (`benchmarks/micro/`)

Pure-function microbenchmarks. No UDP, no TLS, no subprocesses.

| Scenario | Variants | What it measures | Typical runtime | Notes |
|---|---|---|---|---|
| `micro/varint` | `encode` | QUIC varint encode ns/op | < 5s | Absolute gate: p99 <= 250 ns |
| `micro/pacing` | `delay_compute` | Pacing-interval arithmetic | < 5s | Absolute gate: p99 <= 400 ns |
| `micro/header_protection` | `encode`, `decode` | Header-protection mask / unmask ns/op | < 10s | Absolute gate on `decode`: p99 <= 400 µs |
| `micro/aead` | `aes128_gcm`, `chacha20_poly1305` | AEAD seal ns/op at fixed payload size | < 10s | |
| `micro/tls_keygen` | `hkdf_expand_label` | TLS 1.3 traffic-key derivation | < 5s | |
| `micro/frame_serialization` | `stream`, `ack`, `padding`, `crypto`, `reset_stream`, `stop_sending`, `ping`, `goaway`, `window_update`, `max_stream_id`, `connection_close`, `short_header_encode`, `short_header_decode` | Per-frame encode / decode cost + alloc budget | < 30s | Absolute gate: `short_header_{encode,decode}` must have `alloc_bytes == 0` |
| `micro/connection_lookup` | `10`, `100`, `1000`, `10000` | `Endpoint.findConnectionByDcid` cost | < 60s | Guards issue #154 regression |
| `micro/loss_detection_scan` | `100`, `1000`, `10000`, `100000` | ACK processing scan cost | < 60s | Guards issue #90 regression |
| `micro/send_buffer_alloc` | `stream_only`, `stream_plus_ack`, `crypto_handshake`, `initial_padded`, `pto_probe`, `multi_stream_batch` | Per-send-call `ArrayList(u8)` alloc budget for the packet-assembly layer that wraps `Frame.write` (covers `handshake_integration.zig:741-770`, `client.zig:251-332`, `pto.zig:194-231`, `methods_a.zig:220-294`) | < 30s | Guards issue #163 regression; `alloc_bytes` is NON-ZERO pre-fix (no absolute gate; the micro-tier threshold gate is sufficient) |

### Integration tier (`benchmarks/integration/`)

Driven by the runtime: loopback UDP sockets, event-loop polling, real
handshakes (where listed).

| Scenario | Variants | What it measures | Typical runtime | Dependencies |
|---|---|---|---|---|
| `integration/poll_overhead` | `0c`, `1c`, `10c`, `100c`, `1Kc`, `10Kc` | `pollWithStats` cost vs. connection count | < 90s | loopback only |
| `integration/conn_scale` | `1c`, `10c`, `100c`, `1Kc`, `1Kc-100s`, `10Kc`, `10Kc-10s` | Connection + stream setup throughput | < 180s | loopback only; no TLS |
| `integration/udp_batch` | `single`, `batch` | `sendto` vs. `sendmmsg` throughput + syscall count | < 30s | Linux-only (sendmmsg); placeholder rows on non-Linux |
| `integration/handshake_e2e` | `serial`, `10p`, `100p`, `1Kp`, `10Kp` | Initial -> Handshake-complete wall-clock latency | < 300s | real UDP + TLS certs under `./test-certs/` |
| `integration/stream_throughput` | `64B-c1`, `1KB-c1`, `64KB-c1`, `64B-c10`, `1KB-c10`, `1KB-c100` | MB/s + packets-per-second at varying payload / concurrency | < 300s | real UDP + TLS certs |
| `integration/datagram_batch` | `batch_1`, `batch_16`, `batch_64` | Endpoint-mutex hold time under batch RX | < 60s | Guards issue #126 regression |
| `integration/flush_cadence` | `small_writes_1_stream`, `fanout_two_hop`, `burst_flush`, `sustained_writes` | Flush coalescing behaviour + burst / single ratio | < 60s | `burst_flush` currently 9.85x single-write baseline; target <= 1.5x post-fix (geode) |

### External tier (`benchmarks/external/`)

Wraps `test-clients/*` subprocesses. Each scenario spawns the third-
party client against a Zig server at `127.0.0.1:4433` (or
`$QUIC_BENCH_SERVER`) and measures median handshake time. Subprocess
spawn taxes every iteration; compare external rows against other
external rows, not against integration numbers.

| Scenario | Variant | Requires |
|---|---|---|
| `external/quic-go/handshake` | `loopback` | `go` toolchain + `test-clients/quic-go-client` built |
| `external/quinn/handshake` | `loopback` | `cargo` toolchain + `test-clients/quinn-client` built |
| `external/aioquic/handshake` | `loopback` | `python3` + `aioquic` installed + `test-clients/aioquic-client` deps present |

Each scenario emits 20 iterations with 2 warmups, `connection_count=1`
(loopback handshake only). Rows are tagged `external_impl=<name>`.

When a required toolchain is not on `PATH`, the runner emits a
placeholder row with `external_impl=<name>-SKIP`, `iterations=1`,
`wall_time_ns=1`, and `latencies=[0]`. Skipped rows do not count as
FAIL in `scripts/perf-gate.sh`.

### External suite setup

- **Go (quic-go):**

  ```bash
  # toolchain
  sudo apt install golang-go   # or `brew install go`, or mise / asdf
  # build the pre-bundled client
  (cd test-clients/quic-go-client && go build .)
  ```

- **Rust (quinn):**

  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  (cd test-clients/quinn-client && cargo build --release)
  ```

- **Python (aioquic):**

  ```bash
  python3 -m venv .venv && source .venv/bin/activate
  pip install aioquic
  (cd test-clients/aioquic-client && pip install -r requirements.txt)
  ```

## Hardware Sensitivity

Integration and external benchmarks are variance-sensitive. For
reproducible baselines:

- **CPU governor:** `sudo cpupower frequency-set -g performance` (or
  write `performance` to each `cpufreq/*/scaling_governor`).
- **Turbo boost:** disable on Intel via
  `echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo`.
- **SMT / Hyper-Threading:** if A/B runs feel noisy, reboot with the
  `nosmt` kernel parameter or
  `echo off | sudo tee /sys/devices/system/cpu/smt/control`.
- **CPU pinning:** run under `taskset -c 2,3 zig build bench -- ...`
  to keep the bench off CPU 0 (interrupt handling) and any cores
  shared with background work.
- **Quiesce the host:** no `cargo build` / `npm install` / browser /
  IDE indexing during capture. Even a single `zig build` in another
  terminal will skew integration numbers.
- **Thermals:** watch `cpupower frequency-info` or `sensors` between
  captures if the run exceeds a couple of minutes.

The 3x stddev noise floor absorbs moderate variance, but systematic
frequency scaling and thermal throttling can produce silent regression
drift. When in doubt, capture baseline and current within the same
five-minute window on the same hardware.

## Troubleshooting

- **`ENV MISMATCH` from `bench-compare`.** The comparator refuses to
  compare runs with different `zig_version` / `os` / `arch` / `cpu`.
  If you must override (e.g. a Zig minor bump you've decided to
  accept), re-run `zig build bench-compare` with `--skip-env-check`
  passed through, and document the decision in
  [`docs/PERFORMANCE_TRACKING.md`](PERFORMANCE_TRACKING.md). Do not
  waive silently.

- **External suite subprocess hangs.** The 60s watchdog in
  `benchmarks/external/harness.zig` should kill the child and mark
  the row as a timeout. If a `test-clients` subprocess survives past
  that,
  `ps -ef | grep -E 'quic-go-client|quinn-client|aioquic-client'`
  and `kill` manually. Re-run with a higher `warmup_iterations` to
  let the server stabilise before measurement starts.

- **`cert not found` from `handshake_e2e` or `stream_throughput`.**
  The TLS helpers expect `./test-certs/server.pem` +
  `./test-certs/server.key`. Run `./create_test_certs.sh` to
  generate the fixture set.

- **Wildly different ops/sec between runs of the same commit.**
  First check for background load (another `zig build`, a
  `cargo check`, a browser with active tabs). Then check thermal
  throttling and CPU frequency (`cpupower frequency-info`). If the
  variance survives a quiesce + performance-governor pass, pin with
  `taskset` and rerun. The 3x stddev noise floor handles typical
  jitter, but will not rescue you from a loaded box.

- **`mise x zig@0.16.0` not found.** `scripts/perf-gate.sh` prefers
  `mise` for Zig version pinning. If `mise` isn't installed the
  script falls back to ambient `zig` with a WARNING when the version
  doesn't match `0.16.0` — numbers will still compare, but the run
  will not be reproducible against CI. Install `mise` or set
  `ZIG=/path/to/zig-0.16.0/zig` in your shell before invoking the
  script.

- **UDP batch gate fails with "speedup < 0.95x" on a recently-booted
  box.** Socket buffer sizes and CPU scheduling warm up over the
  first few seconds; rerun after the host has been idle for 30s.
  Override the floor only as a last resort with
  `UDP_BATCH_SPEEDUP_MIN=<float> scripts/perf-gate.sh ...` — and add
  a decision-log entry.

## Adding a New Benchmark

1. **Write the scenario module.** Create
   `benchmarks/{micro,integration}/<name>.zig` exposing:

   ```zig
   pub fn run(
       allocator: std.mem.Allocator,
       spec: common.ScenarioSpec,
   ) !common.RunOutput { ... }

   pub const scenarios = [_]common.ScenarioSpec{
       .{
           .name = "<tier>/<name>",
           .variant = "...",
           .iterations = ...,
           .warmup_iterations = ...,
       },
       // one ScenarioSpec per variant
   };
   ```

2. **Register it.** Add the module import + a `SuiteEntry` row to the
   `registry` in `benchmarks/bench_runner.zig`. Verify with
   `zig build bench -- --list` that your scenario appears.

3. **If the scenario carries an absolute gate,** add a row to the
   `absolute_gates` table in `benchmarks/compare.zig` **and** a row
   to the "CI Performance Budgets" or "Integration Tier Targets"
   table in `docs/PERFORMANCE_TARGETS.md`. The two must agree.

4. **Smoke-test and capture a fresh baseline.**

   ```bash
   zig build bench -- --suite=<tier>/<name> --output=/tmp/new.json
   # once the numbers look sane:
   zig build bench -- --suite=all \
       --output=benchmarks/results/baseline.json
   ```

   Add a `docs/PERFORMANCE_TRACKING.md` entry recording the new
   scenario, the hardware used, and any target you proposed.
</content>
