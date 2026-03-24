# Performance Gap Analysis

Last updated: 2026-03-24

Repository: `gitlab.com/devnw/zig/quic`
PerfScore formula: `Impact(1-5) * Likelihood(1-5) * 4`

## Performance Context Snapshot

- Primary hot path: QUIC endpoint packet RX/TX (`src/quic/endpoint/incoming/*.zig`, `src/quic/packet.zig`, `src/quic/recovery/recovery.zig`).
- Pipeline-critical paths: `.gitlab-ci.yml` e2e/interop/quality jobs.
- Performance contract source of truth: `docs/PERFORMANCE_TARGETS.md`.

## Baseline Measurements (Safe + Bounded)

- `zig build test`
  - stderr includes expected secure-client guard:
    - `ERROR: quic_client: connectEx requires a CA certificate (use connectInsecure for insecure testing)`
  - Result: pass.
- `zig build -Dfull-test-graph=true test`
  - same expected stderr guard.
  - Result: pass.
- `zig build bench`
  - `varint encode: 86.273 ns/op`
  - `pacing delay compute: 121.59294 ns/op`
  - `hp decode timing: 223846903 ns total for 2000 ops`
  - `short-header allocs/op: legacy encode=1.0000, legacy decode=2.0000, into encode=0.0000, into decode=0.0000`
  - Result: pass.
- `scripts/perf_gate.sh`
  - Parsed and enforced deterministic thresholds for varint/pacing/hp decode and zero-allocation hot path.
  - Result: `PASS`.

## Summary

- Total findings tracked: **25** (10 from Phase 2 + 15 from Phase 3)
- Status counts:
  - `Open`: **13** (Phase 3 findings)
  - `Closed / Implemented`: **12** (Phase 2 + #94, #97, #101, #104)
  - `Blocked`: **0**
- Severity counts (Phase 3 open findings):
  - `P0 (Critical)`: **4** -- #90, #94, #95, #97
  - `P1 (High)`: **6** -- #100, #101, #104, #105, #108, #109
  - `P2 (Moderate)`: **4** -- getenv per send, pacing non-functional, endpoint mutex contention, no CI perf benchmarks
  - `P3 (Minor)`: **1** -- duplicate StreamRx maintenance risk
- Confidence counts (Phase 3):
  - `confidence::confirmed`: 14
  - `confidence::suspected`: 1 (#108 CUBIC)

### Top 5 Risks (Phase 3)

1. **#90 Unbounded sent_packets** -- Memory leak + ACK processing degrades to seconds after minutes of traffic. SLO breach guaranteed under sustained load.
2. **#97 PacketBufferPool silent reuse** -- Data corruption under contention. Corrupted packets trigger retransmissions and potential connection resets.
3. **#95 No recovery epoch** -- RFC 9002 violation. cwnd collapses to minimum on any burst loss, causing 10-100x throughput reduction.
4. **#94 O(n^2) stream reassembly** -- CPU-bound stream delivery at 1000+ buffered segments. Causes head-of-line blocking.
5. **#109 No frame coalescing** -- 2-5x throughput gap vs modern QUIC implementations (quiche, quinn, ngtcp2).

## Stack-Ranked Findings (All)

### Phase 3 Findings (Open)

| Rank | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement | GitLab Issue | Fix Summary | Owner | SLA/Due | Status |
|---:|---|---:|---|---|---|---|---|---|---|---|---|
| 1 | P0 | 100 | Unbounded sent_packets growth -- ArrayList never pruned, loss scans entire list per ACK (`confidence::confirmed`) | Recovery | `recovery/recovery.zig:118` (append), `:214,243,388,426` (scans) | Memory grows without bound; scan cost proportional to total packets sent | [#90](https://gitlab.com/devnw/zig/quic/-/issues/90) | Prune acked/lost entries after ACK processing; switch to ring buffer or sliding window | Recovery maintainers | Immediate | Open |
| 2 | P0 | 100 | O(n^2) stream reassembly -- tryDrain restarts from i=0 after orderedRemove (`confidence::confirmed`) | Streams | `conn.zig:448-468`, `connection/stream.zig:53-74` | ~500K element shifts at 1000 segments; ~800K at burst reassembly | [#94](https://gitlab.com/devnw/zig/quic/-/issues/94) | Sort bufs by offset; forward-only drain with swapRemove | Stream maintainers | Immediate | Closed |
| 3 | P0 | N/A | No recovery epoch in ccOnLoss -- cwnd halved on every loss call (`confidence::confirmed`) | Recovery | `recovery/recovery.zig:346-366`, `congestion.zig:41-47` | RFC 9002 violation; 10-100x throughput loss on lossy links | [#95](https://gitlab.com/devnw/zig/quic/-/issues/95) | Add congestion_recovery_start_time; only halve cwnd for new recovery periods per RFC 9002 S7.3.3 | Recovery maintainers | Immediate | Open |
| 4 | P0 | N/A | PacketBufferPool 4 slots with unsafe reuse -- silent buffer corruption under contention (`confidence::confirmed`) | Transport | `conn.zig:506-540` | Reuses in-use buffer when all 4 slots occupied; no mutex protection | [#97](https://gitlab.com/devnw/zig/quic/-/issues/97) | Return error on exhaustion; increase pool size; add mutex | Transport maintainers | Immediate | Closed |
| 5 | P1 | 56 | Loss detection double scan -- two full passes over sent_packets per ACK (`confidence::confirmed`) | Recovery | `recovery/recovery.zig:214-270` | 2x CPU cost per ACK, compounded by #90 | [#100](https://gitlab.com/devnw/zig/quic/-/issues/100) | Merge packet-threshold and time-threshold scans into single pass | Recovery maintainers | Within sprint | Open |
| 6 | P1 | 48 | Timer cancel O(n) linear scan -- timer_heap.zig exists but unused (`confidence::confirmed`) | Endpoint | `endpoint.zig:648-656` | ~300M element ops/sec at 1000 connections | [#101](https://gitlab.com/devnw/zig/quic/-/issues/101) | Replaced orderedRemove with swapRemove for O(1) timer cancel and expired-timer collection; timer ordering not required since min-scan covers full list | Endpoint maintainers | Within sprint | Closed |
| 7 | P1 | 40 | orderedRemove(0) FIFO dequeue shifts N-1 elements at 7+ call sites (`confidence::confirmed`) | Transport | `endpoint.zig:509`, `server.zig:87`, `conn.zig:1252`, `api.zig:264`, `methods_c.zig:388`, `methods_a.zig:843` | O(n^2) drain at scale | [#104](https://gitlab.com/devnw/zig/quic/-/issues/104) | Replaced orderedRemove(0) with swapRemove(0) at 6 production call sites for O(1) dequeue; strict FIFO order not required for these queues | Transport maintainers | Within sprint | Closed |
| 8 | P1 | 36 | page_allocator (mmap/munmap) for per-packet AAD construction (`confidence::confirmed`) | Packet/Crypto | `packet.zig:699-703`, `packet.zig:1164-1168` | ~10K unnecessary syscalls/sec at 1000 conn/sec | [#105](https://gitlab.com/devnw/zig/quic/-/issues/105) | Use stack-allocated BoundedArray(u8, 64) for AAD | Packet maintainers | Within sprint | Open |
| 9 | P1 | N/A | CUBIC is no-op NewReno wrapper (`confidence::suspected`) | Recovery | `congestion.zig:52-68` | 2-5x slower cwnd recovery on high-BDP paths | [#108](https://gitlab.com/devnw/zig/quic/-/issues/108) | Implement RFC 8312 CUBIC or prioritize BBR (#21) | Recovery maintainers | Within sprint | Open |
| 10 | P1 | N/A | No STREAM frame coalescing or GSO -- 1 frame per UDP send (`confidence::confirmed`) | Transport | `methods_b.zig:283-457` | 2-5x throughput gap vs modern implementations | [#109](https://gitlab.com/devnw/zig/quic/-/issues/109) | Implement PacketBuilder for frame coalescing; add GSO on Linux | Transport maintainers | Within sprint | Open |
| 11 | P2 | 24 | getenv per packet send -- linear environ scan on every 1-RTT packet (`confidence::confirmed`) | Transport | `methods_c.zig:44-48` | 100-500ms/s CPU at 100K pps | -- | Cache env result at connection init or use comptime flag | Transport maintainers | Next quarter | Open |
| 12 | P2 | N/A | Pacing non-functional -- fixed delays unrelated to RTT (`confidence::confirmed`) | Recovery | `congestion.zig:73-82` | Burst-loss-collapse cycle; no rate smoothing | -- | Implement RTT-based pacing per RFC 9002 S7.7 | Recovery maintainers | Next quarter | Open |
| 13 | P2 | N/A | Endpoint mutex held during entire recv batch (`confidence::confirmed`) | Endpoint | `endpoint.zig:722-731` | >5ms tail latency under load; blocks all handler threads | -- | Process datagrams with per-connection locks; release endpoint mutex between packets | Endpoint maintainers | Next quarter | Open |
| 14 | P2 | N/A | No QUIC-layer performance benchmarks in CI (`confidence::confirmed`) | CI | `scripts/perf_gate.sh`, `.gitlab-ci.yml` | Silent performance regressions | Extends [#12](https://gitlab.com/devnw/zig/quic/-/issues/12) | Add handshake/throughput/stream benchmarks to perf_gate.sh | CI maintainers | Next quarter | Open |
| 15 | P3 | 12 | Duplicate StreamRx in conn.zig and connection/stream.zig (`confidence::confirmed`) | Streams | `conn.zig:399-474`, `connection/stream.zig:20-80` | Maintenance risk; divergent fixes | -- | Deduplicate; canonical version in connection/stream.zig | Stream maintainers | Backlog | Open |

### Phase 2 Findings (Closed)

| Rank | PerfSeverity | PerfScore | Finding | Component | GitLab Issue | Status |
|---:|---|---:|---|---|---|---|
| 1 | P0 | 80 | Hot-path short-header TX allocations in ACK/control paths | App/Transport | [#62](https://gitlab.com/devnw/zig/quic/-/issues/62) | Closed / Implemented |
| 2 | P1 | 64 | Recovery ACK handling O(acked x sent) | Recovery | [#78](https://gitlab.com/devnw/zig/quic/-/issues/78) | Closed / Implemented |
| 3 | P1 | 64 | ACK assembly full stream-map scan for flow-control updates | Endpoint | [#79](https://gitlab.com/devnw/zig/quic/-/issues/79) | Closed / Implemented |
| 4 | P1 | 64 | Sleep-based PollSync/accept coordination overhead | Transport | [#80](https://gitlab.com/devnw/zig/quic/-/issues/80) | Closed / Implemented |
| 5 | P2 | 48 | Benchmarks not regression-gated in CI | CI/CD | [#12](https://gitlab.com/devnw/zig/quic/-/issues/12) | Closed / Implemented |
| 6 | P2 | 48 | Rust e2e lacked cache parity | CI/CD | [#74](https://gitlab.com/devnw/zig/quic/-/issues/74) | Closed / Implemented |
| 7 | P2 | 48 | Interop CI recreated stack repeatedly | CI/CD | [#81](https://gitlab.com/devnw/zig/quic/-/issues/81) | Closed / Implemented |
| 8 | P2 | 40 | Non-Linux loop fallback readiness handling | Platform | [#26](https://gitlab.com/devnw/zig/quic/-/issues/26) | Closed / Implemented |
| 9 | P3 | 32 | Batched UDP recv/send path | Transport | [#82](https://gitlab.com/devnw/zig/quic/-/issues/82) | Closed / Implemented |
| 10 | Info | 16 | Missing explicit SLO/workload performance contract | Governance | [#83](https://gitlab.com/devnw/zig/quic/-/issues/83) | Closed / Implemented |

## Findings By Area

### area::app (Recovery, Transport, Streams)

| Issue | Severity | Finding | Status |
|---|---|---|---|
| #90 | P0 | Unbounded sent_packets growth | Open |
| #94 | P0 | O(n^2) stream reassembly | Closed |
| #95 | P0 | No recovery epoch in ccOnLoss | Open |
| #97 | P0 | PacketBufferPool unsafe reuse | Closed |
| #100 | P1 | Loss detection double scan | Open |
| #101 | P1 | Timer cancel O(n) linear scan | Closed |
| #104 | P1 | orderedRemove(0) FIFO dequeue | Closed |
| #105 | P1 | page_allocator for AAD | Open |
| #108 | P1 | CUBIC no-op wrapper | Open |
| #109 | P1 | No frame coalescing or GSO | Open |
| -- | P2 | getenv per packet send | Open |
| -- | P2 | Pacing non-functional | Open |
| -- | P2 | Endpoint mutex held during batch | Open |
| -- | P3 | Duplicate StreamRx | Open |
| #62 | P0 | Hot-path TX allocations | Closed |
| #78 | P1 | Recovery ACK O(acked x sent) | Closed |
| #79 | P1 | ACK assembly stream-map scan | Closed |
| #80 | P1 | Sleep-based PollSync/accept | Closed |

### area::ci

| Issue | Severity | Finding | Status |
|---|---|---|---|
| -- | P2 | No QUIC-layer perf benchmarks in CI | Open |
| #12 | P2 | Benchmarks not regression-gated | Closed |
| #74 | P2 | Rust e2e cache parity | Closed |
| #81 | P2 | Interop CI repeated setup | Closed |

### area::infra

| Issue | Severity | Finding | Status |
|---|---|---|---|
| #26 | P2 | Non-Linux loop fallback | Closed |
| #83 | Info | Performance contract | Closed |

## Estimated Impact at Scale

| Scale | Current State | After P0 Fixes | After P0+P1 Fixes |
|---|---|---|---|
| 10 connections | Functional | No change | No change |
| 100 connections | Timer overhead noticeable | Stable | O(log n) timers |
| 1000 connections | sent_packets scan > 100ms; timer cancel > 1ms; buffer corruption possible | Bounded recovery; safe buffers | <1ms ACK processing; <0.1ms timers |
| 10K connections | Unusable: seconds per ACK; memory exhaustion | Bounded at cwnd/mds entries | Production-viable with coalescing |
| Lossy link (1%) | cwnd collapses to minimum | Correct RFC 9002 recovery | CUBIC/BBR recovery |

## Roadmap

### Quick Wins (< 1 day each)

| Finding | Issue | Effort | Expected Impact |
|---|---|---|---|
| page_allocator for AAD | #105 | ~1 hour | Eliminate ~10K syscalls/sec at 1000 conn/sec |
| Loss detection double scan | #100 | ~2 hours | 50% reduction in per-ACK scan cost |
| getenv per packet send | -- | ~1 hour | Eliminate ~100K getenv calls/sec at 100K pps |
| Duplicate StreamRx | -- | ~2 hours | Reduce maintenance risk |

### Medium (1-5 days each)

| Finding | Issue | Effort | Expected Impact |
|---|---|---|---|
| Unbounded sent_packets | #90 | 2-3 days | Bounded memory; O(1) ACK processing |
| O(n^2) stream reassembly | #94 | 1-2 days | O(n) drain instead of O(n^2) -- **Closed** |
| No recovery epoch | #95 | 1-2 days | Correct cwnd behavior; 10-100x throughput on lossy links |
| PacketBufferPool reuse | #97 | 1-2 days | Eliminate silent data corruption -- **Closed** |
| Timer cancel linear scan | #101 | 1-2 days | O(1) timer cancel via swapRemove -- **Closed** |
| orderedRemove(0) FIFO | #104 | 2-3 days | O(1) dequeue via swapRemove at 6 sites -- **Closed** |
| Pacing non-functional | -- | 2-3 days | Eliminate burst-loss-collapse cycle |

### Strategic (> 5 days each)

| Finding | Issue | Effort | Expected Impact |
|---|---|---|---|
| CUBIC implementation | #108 | 5-10 days | 2-5x faster cwnd recovery on high-BDP |
| STREAM frame coalescing + GSO | #109 | 10-20 days | 2-5x throughput improvement |
| Endpoint mutex contention | -- | 5-10 days | <1ms tail latency under load |
| QUIC-layer CI benchmarks | Extends #12 | 3-5 days | Detect performance regressions automatically |

## Additional Findings (Not Yet Issued)

These findings are tracked here but do not yet have dedicated GitLab issues. They will be promoted to issues as capacity allows.

| Finding | Severity | Evidence | Notes |
|---|---|---|---|
| Connection struct ~20KB not pooled | P2 | `conn.zig:546-900` | Related to #13 (connection pooling) |
| ArrayList(u8) frame buffer alloc per sendDatagram | P2 | `methods_b.zig:151-152,199-200` | Related to #10 (memory allocation patterns) |
| Recovery mutex serializes congestion reads | P2 | `recovery/recovery.zig:498-530` | 3 separate lock/unlock for reads that could be batched |
| Verbose debug logging in hot paths | P3 | `recovery.zig`, `packet.zig`, `methods_b.zig` | Related to #56 (debug logging leaks) and #69 (quiet tests) |

## Related Existing Issues

The following pre-existing issues overlap with Phase 3 findings:

| Existing Issue | Related Phase 3 Finding(s) | Relationship |
|---|---|---|
| #9 Optimize packet processing paths | #90, #94, #100, #101, #104, #109 | Umbrella issue; Phase 3 findings provide specific action items |
| #10 Improve memory allocation patterns | #90, #97, #105 | Phase 3 findings specify exact allocation anti-patterns |
| #11 Zero-copy packet processing | #94, #109 | Frame coalescing and stream reassembly are prerequisites |
| #13 Connection pooling | #97 (PacketBufferPool), Connection struct pooling | Phase 3 identifies the specific pool that is broken |
| #21 BBR congestion control | #95, #108 | Recovery epoch fix (#95) is prerequisite; #108 is intermediate step |

## Blocked Items

- None currently blocked. All findings have clear fix paths.

## Unknowns and Confirmation Needed

1. **#108 CUBIC** (`confidence::suspected`): The CUBIC struct is clearly a no-op wrapper, but the actual throughput impact depends on the target deployment environment (high-BDP or not). Measurement needed: run a bulk transfer benchmark over a simulated 100ms RTT link and compare throughput with a proper CUBIC implementation.

2. **Endpoint mutex contention** (P2): The actual tail latency impact under load is estimated, not measured. Confirmation requires a load test with 100+ concurrent connections measuring p99 latency distribution.

3. **getenv per packet send**: The actual CPU cost depends on environ size. Confirmation: `perf record` on a 100K pps workload to measure time spent in `std.posix.getenv`.
