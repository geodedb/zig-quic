# QUIC Benchmark System Design

**Date:** 2026-03-27
**Status:** Approved
**Scope:** Enterprise-grade benchmark suite for connection scaling, stream multiplexing, throughput, and poll loop performance

## Problem

The QUIC implementation lacks production-grade benchmarks. Existing `bench/` micro-benchmarks cover crypto and codec operations but not connection scaling, stream multiplexing, or end-to-end throughput. A 15x QPS regression (281 -> 19 QPS) went undetected because there was no baseline system. Enterprise readiness requires validated performance at thousands of concurrent connections.

## Architecture

### Directory Structure

```
benchmarks/                      # NEW: macro-benchmarks with baselines
  scale_bench.zig                # Connection/stream scaling (loopback)
  throughput_bench.zig           # MB/s payload throughput (real UDP)
  handshake_bench.zig            # TLS handshake latency at scale (real UDP)
  poll_bench.zig                 # Poll loop overhead profiling (loopback)
  compare.zig                    # Regression detection tool
  common.zig                     # Shared harness: timing, JSON output, tier configs
  results/
    baseline.json                # Accepted performance standard
    <sha>.json                   # Per-commit snapshots
    README.md                    # Format documentation

bench/                           # EXISTING: micro-benchmarks (unchanged)
  main.zig                       # Congestion control + packet encoding
  bench_tls_aead.zig             # AEAD crypto
  bench_tls_handshake.zig        # Key derivation
  udp_batch_bench.zig            # UDP syscall efficiency
```

### Separation of Concerns

- `bench/` stays as-is: fast micro-benchmarks for crypto, codec, and UDP syscall efficiency.
- `benchmarks/` is the new macro-benchmark suite following graph-storage's pattern: JSON output, persistent baselines, automated regression detection.
- `tests/test_poll_perf.zig` remains as a quick unit test gate in `zig build test`.

## Benchmark Suites

### 1. scale_bench.zig -- Connection/Stream Scaling (Loopback)

Measures server-side capacity using loopback transport (no real network I/O). Isolates Zig QUIC stack performance from OS/network variance.

**7 tiers:**

| Tier | Connections | Streams/Conn | Total Streams |
|------|------------|--------------|---------------|
| 1c | 1 | 1 | 1 |
| 10c | 10 | 10 | 100 |
| 100c | 100 | 10 | 1,000 |
| 1Kc | 1,000 | 10 | 10,000 |
| 1Kc-100s | 1,000 | 100 | 100,000 |
| 10Kc | 10,000 | 1 | 10,000 |
| 10Kc-10s | 10,000 | 10 | 100,000 |

**Metrics per tier:**

| Metric | Kind | Unit | Description |
|--------|------|------|-------------|
| conn_setup_ops_sec | throughput | ops/sec | Connection creation rate |
| poll_ns | latency | ns/poll | Per-poll-cycle overhead |
| stream_open_ns | latency | ns/op | Stream open latency |
| stream_write_ns | latency | ns/op | Write 1KB to stream |
| stream_read_ns | latency | ns/op | Read 1KB from stream |
| stream_roundtrip_ns | latency | ns/op | Write-read echo round-trip |
| accept_rate_ops_sec | throughput | ops/sec | Server accept throughput |
| mixed_ops_sec | throughput | ops/sec | 70% read, 20% write, 10% open/close |

**Dynamic iteration counts:** 5000 for 1c, 2000 for 10c, 500 for 100c, 200 for 1Kc, 100 for 10Kc tiers.

### 2. throughput_bench.zig -- Payload Throughput (Real UDP)

Measures end-to-end data transfer rates using real UDP sockets on localhost. Zig client + Zig server, no Go dependency.

**4 payload sizes x 3 concurrency levels:**

| Payload | c=1 | c=10 | c=100 |
|---------|-----|------|-------|
| 64B | measured | measured | measured |
| 1KB | measured | measured | measured |
| 64KB | measured | measured | measured |
| 1MB | measured | measured | measured |

**Metrics per cell:** `throughput_mbps`, `packets_per_sec`, `avg_latency_us`, `p99_latency_us`

**Implementation:** Spawn server thread with echo loop. Client threads each create an endpoint, connect over localhost UDP, send payload, measure round-trip. Aggregate after all threads join.

### 3. handshake_bench.zig -- Handshake Latency (Real UDP)

Measures TLS 1.3 handshake completion time at scale using real UDP.

**5 tiers:**

| Tier | Concurrent Handshakes |
|------|-----------------------|
| serial | 1 at a time |
| 10p | 10 parallel |
| 100p | 100 parallel |
| 1Kp | 1,000 parallel |
| 10Kp | 10,000 parallel |

**Metrics:** `handshake_avg_ms`, `handshake_p99_ms`, `handshake_rate_per_sec`, `handshake_fail_rate`

### 4. poll_bench.zig -- Poll Loop Profiling (Loopback)

Measures pollWithStats() overhead as a function of connection count. Loopback transport for reproducibility.

**6 tiers:** 0, 1, 10, 100, 1K, 10K connections

**Metrics:** `polls_per_sec`, `us_per_poll`, `timer_processing_ns`, `pto_arming_ns`

## JSON Output Format

All four benchmark executables emit the same envelope to stdout. Human-readable tables go to stderr.

```json
{
  "version": 1,
  "suite": "scale",
  "timestamp": "2026-03-27T14:30:00Z",
  "git_commit": "abc1234",
  "system": { "os": "linux", "arch": "x86_64" },
  "tiers": [
    {
      "name": "100c",
      "params": { "connections": 100, "streams_per_conn": 10 },
      "metrics": {
        "conn_setup_ops_sec": 45000,
        "poll_ns": 12400,
        "stream_roundtrip_ns": 890,
        "mixed_ops_sec": 180000
      }
    }
  ]
}
```

### Human-Readable Output (stderr)

```
============================================================================
  QUIC scale benchmark
============================================================================

  Tier       Conns  Streams  Setup/s   Poll(ns) Open(ns) RT(ns)  Mixed/s
---------- ------- -------- --------- -------- -------- ------- --------
  1c             1        1    125000     8200      420     890   280000
  100c         100     1000     45000    12400      480     920   180000
  10Kc       10000    10000      8200    85000      620    1400    42000
```

## Regression Detection

### compare.zig

Reads two JSON files with matching `suite` fields. Computes delta percentage per metric per tier. Exits 1 if any metric regresses beyond its threshold.

**Metric classification:**

| Pattern | Kind | Default Threshold |
|---------|------|-------------------|
| `*_ops_sec`, `*_mbps`, `*_per_sec`, `*_pps` | higher_is_better | 15% |
| `*_ns`, `*_ms`, `*_us` | lower_is_better | 20% |
| `polls_per_sec` | higher_is_better | 25% |

**Output:**

```
Suite: scale
Tier      Metric                Baseline      Current    Delta%  Status
--------- -------------------- ------------ ----------- ------- ------
1c        poll_ns                      8200        8500   +3.7%  PASS
100c      mixed_ops_sec              180000      148000  -17.8%  FAIL
```

Supports `--threshold <pct>` override for all metrics.

## Makefile Targets

```makefile
bench-scale:       Run scale_bench (loopback, connection/stream scaling)
bench-throughput:  Run throughput_bench (real UDP, MB/s)
bench-handshake:   Run handshake_bench (real UDP, TLS handshake latency)
bench-poll:        Run poll_bench (loopback, poll loop overhead)
bench-all:         Run all benchmarks (existing micro + new macro)

bench-save:        Run scale_bench, save JSON to benchmarks/results/<sha>.json
bench-baseline:    Run scale_bench, save JSON to benchmarks/results/baseline.json
bench-compare:     Run scale_bench, compare JSON against baseline.json (exit 1 on regression)
```

`bench-save`, `bench-baseline`, `bench-compare` default to `scale_bench` (most stable for regression tracking). Pass `SUITE=throughput|handshake|poll` to use a different suite.

## Build Integration

Each benchmark is a separate executable registered in build.zig:

```
zig build bench-scale     -- [max-tier]
zig build bench-poll      -- [max-conns]
zig build bench-throughput -- [payload] [concurrency]
zig build bench-handshake  -- [max-parallel]
```

All compiled as `ReleaseFast`. `common.zig` is a shared module imported by all four executables.

**Module imports needed:**
- `quic_endpoint` -- endpoint creation, poll, connection management
- `quic_conn` -- connection types, stream I/O
- `quic_config` -- QuicConfig
- `quic_api` -- high-level API (for throughput/handshake real-UDP benchmarks)

## Loopback Transport

scale_bench and poll_bench use a loopback transport that bypasses real UDP:

1. Server endpoint created with `LoopbackTransport` -- in-memory ring buffer pair, no syscalls
2. Client connections added via `connectClient()` (already works in tests)
3. Datagrams injected via `processIncomingDatagram()` (already exposed)

This isolates Zig server performance from OS/network variance and produces reproducible baselines.

## Real UDP Benchmarks

throughput_bench and handshake_bench use real localhost UDP:

1. Server thread running QUIC server event loop (echo pattern from cmd/quic-server.zig)
2. N client threads, each creating a QUIC endpoint, connecting, running workload
3. Client-side timing with nanoTimestamp, aggregated after join

Uses Zig client endpoints (not Go quic-go) to avoid external runtime noise.

## Performance Targets (Initial Baselines)

These are aspirational targets that will be calibrated after the first run:

| Metric | Target | Notes |
|--------|--------|-------|
| Connection setup rate | >10K/sec at 1c | Loopback, no TLS |
| Poll overhead at 100 conns | <50us/poll | After Phase 1 removal optimization |
| Poll overhead at 10K conns | <500us/poll | Requires PTO early-exit optimization |
| Stream round-trip at 1c | <10us | Loopback |
| Throughput at 1KB c=1 | >100 MB/s | Real UDP localhost |
| Handshake rate serial | >500/sec | Real UDP with TLS |

## What Changes vs Stays

- **Keep unchanged:** All `bench/` micro-benchmarks, `tests/test_poll_perf.zig`
- **New:** `benchmarks/` directory with 4 executables + compare tool + common module
- **New:** `benchmarks/results/` with baseline.json tracking
- **New:** Makefile targets for bench-scale, bench-throughput, bench-handshake, bench-poll, bench-all, bench-save, bench-baseline, bench-compare
- **New:** build.zig registrations for 5 new executables (4 benchmarks + compare)
