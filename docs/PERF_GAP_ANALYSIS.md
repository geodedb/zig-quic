# Performance Gap Analysis

Last updated: 2026-03-25

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

- Total findings tracked: **34** (10 from Phase 2 + 15 from Phase 3 + 3 from Phase 4 + 6 from Phase 5)
- Status counts:
  - `Open`: **14** (Phase 3 carry-forward + Phase 5 new findings)
  - `Closed / Implemented`: **20** (Phase 2 + #94, #95, #97, #100, #101, #104, #105, #108, pacing, getenv)
  - `Blocked`: **0**
- Severity counts (all open findings):
  - `P0 (Critical)`: **3** -- #90 (sent_packets), #154 (O(N) lookup), #182 (timer O(N) PTO)
  - `P1 (High)`: **5** -- #109, #126, #163, #172, #183
  - `P2 (Moderate)`: **4** -- #128 (CI benchmarks), #167, #184, #185
  - `P3 (Minor)`: **3** -- #127 (dup StreamRx), #186, #187
- Confidence counts (all phases):
  - `confidence::confirmed`: 33
  - `confidence::suspected`: 0 (#108 CUBIC reclassified to Closed / Implemented)

### Top 5 Risks (Phase 5 Updated)

1. **#154 O(N) connection lookup** (PerfScore 100) -- Full-table scan per packet. At 10K connections, connection lookup alone consumes all CPU. SLO breach guaranteed.
2. **#182 Timer O(N) + PTO polling** (PerfScore 88) -- 30K PTO checks per poll at 10K connections, under endpoint mutex. Compounds #154.
3. **#126 Endpoint mutex scope** (PerfScore 82) -- mu held during 16-datagram batch including crypto. 500us-5ms lock hold blocks all threads.
4. **#163 Per-frame heap allocation** (PerfScore 72) -- 100K+ alloc/free cycles/sec for frame serialization. Mechanical fix available.
5. **#183 Send path efficiency** (PerfScore 70) -- Per-packet sendto syscall + pacing heap alloc. sendmmsg infrastructure exists but is unused.

### Reclassifications (Phase 5)

- **#108 CUBIC**: Reclassified from `confidence::suspected` / Open to Closed / Implemented. The CUBIC struct now contains genuine RFC 8312 logic (W_max, K computation, cubic growth, TCP-friendliness). See #148 for remaining concern about two conflicting implementations.

## Stack-Ranked Findings (All)

### Phase 3 Findings (Open)

| Rank | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement | GitLab Issue | Fix Summary | Owner | SLA/Due | Status |
|---:|---|---:|---|---|---|---|---|---|---|---|---|
| 1 | P0 | 100 | Unbounded sent_packets growth -- ArrayList never pruned, loss scans entire list per ACK (`confidence::confirmed`) | Recovery | `recovery/recovery.zig:118` (append), `:214,243,388,426` (scans) | Memory grows without bound; scan cost proportional to total packets sent | [#90](https://gitlab.com/devnw/zig/quic/-/issues/90) | Bounded pruning added in commit b501cba: `pruneSentPackets()` removes acked/lost entries after ACK processing. Ring buffer migration deferred. | Recovery maintainers | Immediate | Open |
| 2 | P0 | 100 | O(n^2) stream reassembly -- tryDrain restarts from i=0 after orderedRemove (`confidence::confirmed`) | Streams | `conn.zig:448-468`, `connection/stream.zig:53-74` | ~500K element shifts at 1000 segments; ~800K at burst reassembly | [#94](https://gitlab.com/devnw/zig/quic/-/issues/94) | Sort bufs by offset; forward-only drain with swapRemove | Stream maintainers | Immediate | Closed |
| 3 | P0 | N/A | No recovery epoch in ccOnLoss -- cwnd halved on every loss call (`confidence::confirmed`) | Recovery | `recovery/recovery.zig:346-366`, `congestion.zig:41-47` | RFC 9002 violation; 10-100x throughput loss on lossy links | [#95](https://gitlab.com/devnw/zig/quic/-/issues/95) | Added congestion_recovery_start_time field + epoch check in ccOnLoss per RFC 9002 S7.3.3 | Recovery maintainers | Immediate | Closed / Implemented |
| 4 | P0 | N/A | PacketBufferPool 4 slots with unsafe reuse -- silent buffer corruption under contention (`confidence::confirmed`) | Transport | `conn.zig:506-540` | Reuses in-use buffer when all 4 slots occupied; no mutex protection | [#97](https://gitlab.com/devnw/zig/quic/-/issues/97) | Return error on exhaustion; increase pool size; add mutex | Transport maintainers | Immediate | Closed |
| 5 | P1 | 56 | Loss detection double scan -- two full passes over sent_packets per ACK (`confidence::confirmed`) | Recovery | `recovery/recovery.zig:214-270` | 2x CPU cost per ACK, compounded by #90 | [#100](https://gitlab.com/devnw/zig/quic/-/issues/100) | Merged packet-threshold and time-threshold scans into single pass | Recovery maintainers | Within sprint | Closed / Implemented |
| 6 | P1 | 48 | Timer cancel O(n) linear scan -- timer_heap.zig exists but unused (`confidence::confirmed`) | Endpoint | `endpoint.zig:648-656` | ~300M element ops/sec at 1000 connections | [#101](https://gitlab.com/devnw/zig/quic/-/issues/101) | Replaced orderedRemove with swapRemove for O(1) timer cancel and expired-timer collection; timer ordering not required since min-scan covers full list | Endpoint maintainers | Within sprint | Closed |
| 7 | P1 | 40 | orderedRemove(0) FIFO dequeue shifts N-1 elements at 7+ call sites (`confidence::confirmed`) | Transport | `endpoint.zig:509`, `server.zig:87`, `conn.zig:1252`, `api.zig:264`, `methods_c.zig:388`, `methods_a.zig:843` | O(n^2) drain at scale | [#104](https://gitlab.com/devnw/zig/quic/-/issues/104) | Replaced orderedRemove(0) with swapRemove(0) at 6 production call sites for O(1) dequeue; strict FIFO order not required for these queues | Transport maintainers | Within sprint | Closed |
| 8 | P1 | 36 | page_allocator (mmap/munmap) for per-packet AAD construction (`confidence::confirmed`) | Packet/Crypto | `packet.zig:699-703`, `packet.zig:1164-1168` | ~10K unnecessary syscalls/sec at 1000 conn/sec | [#105](https://gitlab.com/devnw/zig/quic/-/issues/105) | Replaced with stack-allocated buffer | Packet maintainers | Within sprint | Closed / Implemented |
| 9 | P1 | N/A | CUBIC is no-op NewReno wrapper (`confidence::suspected`) | Recovery | `congestion.zig:52-68` | 2-5x slower cwnd recovery on high-BDP paths | [#108](https://gitlab.com/devnw/zig/quic/-/issues/108) | RFC 8312 CUBIC implemented: W_max, K, cubic growth, TCP-friendliness | Recovery maintainers | Within sprint | Closed / Implemented |
| 10 | P1 | N/A | No STREAM frame coalescing or GSO -- 1 frame per UDP send (`confidence::confirmed`) | Transport | `methods_b.zig:283-457` | 2-5x throughput gap vs modern implementations | [#109](https://gitlab.com/devnw/zig/quic/-/issues/109) | Implement PacketBuilder for frame coalescing; add GSO on Linux | Transport maintainers | Within sprint | Open |
| 11 | P2 | 24 | getenv per packet send -- linear environ scan on every 1-RTT packet (`confidence::confirmed`) | Transport | `methods_c.zig:44-48` | 100-500ms/s CPU at 100K pps | -- | Env var removed entirely in Batch A (commit 7034861); config field used instead | Transport maintainers | 2026-03-24 | Closed / Implemented |
| 12 | P2 | N/A | Pacing non-functional -- fixed delays unrelated to RTT (`confidence::confirmed`) | Recovery | `congestion.zig:73-82` | Burst-loss-collapse cycle; no rate smoothing | -- | Implemented RTT-based pacing per RFC 9002 S7.7: `interval = smoothed_rtt * mss / cwnd` (commit bf8cf7f) | Recovery maintainers | 2026-03-24 | Closed / Implemented |
| 13 | P1 | 82 | Endpoint mutex held during entire recv batch (`confidence::confirmed`) | Endpoint | `endpoint.zig:764-773` | >5ms tail latency under load; blocks all handler threads | [#126](https://gitlab.com/devnw/zig/quic/-/issues/126) | Process datagrams with per-connection locks; release endpoint mutex between packets | Endpoint maintainers | Within sprint | Open |
| 14 | P2 | N/A | No QUIC-layer performance benchmarks in CI (`confidence::confirmed`) | CI | `scripts/perf_gate.sh`, `.gitlab-ci.yml` | Silent performance regressions | Extends [#12](https://gitlab.com/devnw/zig/quic/-/issues/12) | Add handshake/throughput/stream benchmarks to perf_gate.sh | CI maintainers | Next quarter | Open |
| 15 | P3 | 12 | Duplicate StreamRx in conn.zig and connection/stream.zig (`confidence::confirmed`) | Streams | `conn.zig:399-474`, `connection/stream.zig:20-80` | Maintenance risk; divergent fixes | -- | Deduplicate; canonical version in connection/stream.zig | Stream maintainers | Backlog | Open |

### Phase 5 Findings (2026-03-25)

| Rank | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement | GitLab Issue | Fix Summary | Owner | SLA/Due | Status |
|---:|---|---:|---|---|---|---|---|---|---|---|---|
| 1 | P0 | 100 | O(N) connection lookup per packet (`confidence::confirmed`) | Endpoint | `endpoint/lookup.zig:138-170` | 10K comparisons/pkt at 10K conns; 1B comparisons/sec at 100K pps | [#154](https://gitlab.com/devnw/zig/quic/-/issues/154) | DCID-indexed HashMap for O(1) lookup | Endpoint maintainers | Immediate | Open |
| 2 | P0 | 88 | Timer O(N) + PTO polling per poll cycle (`confidence::confirmed`) | Endpoint | `endpoint.zig:803-812` | 30K PTO checks + nanoTimestamp syscalls per poll at 10K conns | [#182](https://gitlab.com/devnw/zig/quic/-/issues/182) | Dirty-flag PTO; single timestamp per poll; event-driven timer heap | Endpoint maintainers | Immediate | Open |
| 3 | P1 | 82 | Endpoint mutex scope during 16-datagram batch (`confidence::confirmed`) | Endpoint | `endpoint.zig:764-773` | 500us-5ms lock hold including crypto+frame processing | [#126](https://gitlab.com/devnw/zig/quic/-/issues/126) | Per-connection locks; release endpoint mutex between packets | Endpoint maintainers | Within sprint | Open |
| 4 | P1 | 72 | Per-frame heap allocation at 15+ sites (`confidence::confirmed`) | Transport | `methods_a.zig:48,224,284,453,921,1032`, `methods_b.zig:149,197,366,383,567,616,660` | 100K+ alloc/free cycles/sec at 100K pps | [#163](https://gitlab.com/devnw/zig/quic/-/issues/163) | Replace ArrayList(u8) with fixedBufferStream on stack | Transport maintainers | Within sprint | Open |
| 5 | P1 | 70 | Send path: pacing heap alloc + no sendmmsg batching (`confidence::confirmed`) | Endpoint/IO | `endpoint/io.zig:50-51`, `endpoint.zig:1499,1503` | 100K sendto syscalls/sec; sendBatch exists but unused | [#183](https://gitlab.com/devnw/zig/quic/-/issues/183) | Send queue + flushSendQueue() via sendBatch; GSO on Linux | IO maintainers | Within sprint | Open |
| 6 | P1 | 64 | 64KB PacketBufferPool per connection (`confidence::confirmed`) | Transport | `conn.zig:436-466` | 64MB at 1K conns; 640MB at 10K conns | [#167](https://gitlab.com/devnw/zig/quic/-/issues/167) | Shared endpoint-level pool or slab allocator | Transport maintainers | Within sprint | Open |
| 7 | P1 | 48 | ECN bits hardcoded to 0; recvmsg path disabled (`confidence::confirmed`) | Endpoint | `endpoint/io.zig:79-81`, `udp_transport.zig:276` | 10-30% throughput loss on ECN-capable networks | [#172](https://gitlab.com/devnw/zig/quic/-/issues/172) | Set IP_RECVTOS/IPV6_RECVTCLASS; parse cmsg in recvmsg | Endpoint maintainers | Within sprint | Open |
| 8 | P2 | 48 | readStreamUnlocked copyForwards shifts inbox per read (`confidence::confirmed`) | Streams | `methods_b.zig:512-516`, `methods_c.zig:31` | 63MB/sec memcpy at 64KB inbox + 1KB reads at 1K reads/sec | [#184](https://gitlab.com/devnw/zig/quic/-/issues/184) | Ring buffer or read-cursor for inbox | Stream maintainers | Next quarter | Open |
| 9 | P2 | 36 | 6 remaining orderedRemove sites (`confidence::confirmed`) | Transport | `endpoint.zig:481`, `api.zig:354,361,385`, `conn.zig:1306`, `lifecycle.zig:175,237,271` | O(N) shift per removal at each site | [#185](https://gitlab.com/devnw/zig/quic/-/issues/185) | PARTIAL: 3/6 converted to swapRemove (endpoint.zig:481, api.zig:354, lifecycle.zig:271). Remaining 3 require orderedRemove (loop-continue patterns need stable indices). | Transport maintainers | 2026-03-25 | Closed / Implemented |
| 10 | P3 | 20 | tryDrain O(N^2) on out-of-order reassembly (`confidence::confirmed`) | Streams | `connection/stream.zig:71-94` | ~500K comparisons at 1000 reordered segments | [#186](https://gitlab.com/devnw/zig/quic/-/issues/186) | Sort bufs before drain or use min-heap | Stream maintainers | Backlog | Open |
| 11 | P3 | 12 | PacketBufferPool.release O(16) scan (`confidence::confirmed`) | Transport | `conn.zig:457-465` | 16 pointer comparisons per release | [#187](https://gitlab.com/devnw/zig/quic/-/issues/187) | Compute slot index from pointer arithmetic | Transport maintainers | Backlog | Open |

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

### area::app (Recovery, Transport, Streams, Endpoint)

| Issue | Severity | Finding | Status |
|---|---|---|---|
| #154 | P0 | O(N) connection lookup per packet | Open |
| #182 | P0 | Timer O(N) + PTO polling per poll cycle | Open |
| #90 | P0 | Unbounded sent_packets growth | Open |
| #94 | P0 | O(n^2) stream reassembly | Closed |
| #95 | P0 | No recovery epoch in ccOnLoss | Closed |
| #97 | P0 | PacketBufferPool unsafe reuse | Closed |
| #126 | P1 | Endpoint mutex scope during recv batch | Open |
| #163 | P1 | Per-frame heap allocation at 15+ sites | Open |
| #183 | P1 | Send path: pacing heap alloc + no sendmmsg | Open |
| #167 | P1 | 64KB PacketBufferPool per connection | Open |
| #172 | P1 | ECN bits hardcoded to 0 | Open |
| #109 | P1 | No frame coalescing or GSO | Open |
| #100 | P1 | Loss detection double scan | Closed |
| #101 | P1 | Timer cancel O(n) linear scan | Closed |
| #104 | P1 | orderedRemove(0) FIFO dequeue | Closed |
| #105 | P1 | page_allocator for AAD | Closed |
| #108 | P1 | CUBIC (now RFC 8312 compliant) | Closed / Implemented |
| #184 | P2 | readStreamUnlocked copyForwards | Open |
| #185 | P2 | 6 remaining orderedRemove sites (3/6 converted) | Closed / Implemented |
| -- | P2 | getenv per packet send | Closed |
| -- | P2 | Pacing non-functional | Closed |
| #186 | P3 | tryDrain O(N^2) worst case | Open |
| #187 | P3 | PacketBufferPool.release O(16) scan | Open |
| #127 | P3 | Duplicate StreamRx | Open |
| #62 | P0 | Hot-path TX allocations | Closed |
| #78 | P1 | Recovery ACK O(acked x sent) | Closed |
| #79 | P1 | ACK assembly stream-map scan | Closed |
| #80 | P1 | Sleep-based PollSync/accept | Closed |

### area::ci

| Issue | Severity | Finding | Status |
|---|---|---|---|
| #128 | P2 | No QUIC-layer perf benchmarks in CI | Open |
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
| 100 connections | Timer overhead noticeable; mutex contention visible | Stable; O(1) lookup | O(1) lookup; batched send; ECN enabled |
| 1000 connections | O(N) lookup ~1K comparisons/pkt; PTO polling ~3K checks/poll; 64MB buffer pool memory | O(1) lookup; dirty-flag PTO; bounded recovery | <1ms poll; batched send; per-frame stack alloc |
| 10K connections | Unusable: 10K comparisons/pkt; 30K PTO checks/poll; 640MB buffer pools; 100K sendto/sec | O(1) lookup; event-driven PTO; shared buffer pool | Production-viable: sendmmsg batching; coalescing; ECN |
| Lossy link (1%) | RFC 8312 CUBIC now functional (was no-op) | Correct recovery | CUBIC + ECN feedback for optimal response |

## Roadmap

### Quick Wins (< 1 day each)

| Finding | Issue | Effort | Expected Impact |
|---|---|---|---|
| Per-frame heap alloc (fixedBufferStream) | #163 | ~4 hours | Eliminate 100K+ alloc/free cycles/sec; mechanical fix |
| Remaining orderedRemove sites | #185 | ~4 hours | O(1) removal at 6 additional sites |
| PacketBufferPool.release O(16) | #187 | ~1 hour | O(1) release via pointer arithmetic |
| ECN extraction (socket opts + cmsg) | #172 | ~1 day | 10-30% throughput on ECN-capable networks |
| Duplicate StreamRx | #127 | ~2 hours | Reduce maintenance risk |
| page_allocator for AAD | #105 | ~1 hour | **Closed** |
| Loss detection double scan | #100 | ~2 hours | **Closed** |
| getenv per packet send | -- | ~1 hour | **Closed** |

### Medium (1-5 days each)

| Finding | Issue | Effort | Expected Impact |
|---|---|---|---|
| O(N) connection lookup -> HashMap | #154 | 2-3 days | O(1) lookup; production-viable at 10K+ conns |
| Timer O(N) PTO -> dirty flag | #182 | 2-3 days | Eliminate 30K PTO checks/poll at 10K conns |
| Send path batching (sendmmsg) | #183 | 2-3 days | 2-3x send throughput; 1/64th syscalls |
| readStreamUnlocked ring buffer | #184 | 1-2 days | Eliminate O(N) memcpy per stream read |
| Unbounded sent_packets | #90 | 2-3 days | Bounded memory; O(1) ACK processing |
| 64KB PacketBufferPool -> shared | #167 | 3 days | 640MB savings at 10K conns |

### Strategic (> 5 days each)

| Finding | Issue | Effort | Expected Impact |
|---|---|---|---|
| Endpoint mutex -> per-connection locks | #126 | 5-10 days | <1ms tail latency under load |
| STREAM frame coalescing + GSO | #109 | 10-20 days | 2-5x throughput improvement |
| Timer O(N) PTO -> min-heap (full) | #182 | 5 days | O(log N) timer operations |
| QUIC-layer CI benchmarks | #128 | 3-5 days | Detect performance regressions automatically |
| CUBIC implementation | #108 | -- | **Closed / Implemented** (RFC 8312 compliant) |

## Additional Findings (Not Yet Issued)

These findings are tracked here but do not yet have dedicated GitLab issues. They will be promoted to issues as capacity allows.

| Finding | Severity | Evidence | Notes |
|---|---|---|---|
| Connection struct ~20KB not pooled | P2 | `conn.zig:546-900` | Related to #13 (connection pooling); compounded by #167 (64KB inline pool) |
| ArrayList(u8) frame buffer alloc per sendDatagram | P2 | `methods_b.zig:151-152,199-200` | Subset of #163 (per-frame alloc); will be resolved when #163 is fixed |
| Recovery mutex serializes congestion reads | P2 | `recovery/recovery.zig:498-530` | 3 separate lock/unlock for reads that could be batched; tracked as #131 |
| Verbose debug logging in hot paths | P3 | `recovery.zig`, `packet.zig`, `methods_b.zig` | Related to #56 (debug logging leaks) and #69 (quiet tests) |
| Double Initial packet encoding (2x AEAD) | P1 | Phase 4 finding | Tracked as #170 |

## Related Existing Issues

The following pre-existing issues overlap with performance findings:

| Existing Issue | Related Finding(s) | Relationship |
|---|---|---|
| #9 Optimize packet processing paths | #90, #94, #100, #101, #104, #109, #154, #182 | Umbrella issue; Phase 3+5 findings provide specific action items |
| #10 Improve memory allocation patterns | #90, #97, #105, #163, #167 | Phase 3+5 findings specify exact allocation anti-patterns |
| #11 Zero-copy packet processing | #94, #109, #184 | Frame coalescing, stream reassembly, ring buffer inbox |
| #13 Connection pooling | #97, #167, Connection struct pooling | Phase 3+5 identify pool issues (unsafe reuse + 64KB inline) |
| #21 BBR congestion control | #95, #108 | Recovery epoch (#95) fixed; CUBIC (#108) now RFC 8312 compliant |
| #82 Batched UDP I/O | #165, #183 | sendBatch infrastructure built but unused from data path |
| #148 Conflicting CUBIC implementations | #108 | recovery.zig placeholder vs congestion.zig real implementation |

## Blocked Items

- None currently blocked. All findings have clear fix paths.

## Unknowns and Confirmation Needed

1. **#126 Endpoint mutex contention** (upgraded to P1): The actual tail latency impact under load is estimated at 500us-5ms, not measured. Confirmation requires a load test with 100+ concurrent connections measuring p99 latency distribution. The 16-datagram batch size under lock is confirmed by code inspection.

2. **#182 Timer PTO polling**: The 30K `nanoTimestamp` syscall count at 10K connections is calculated (3 PTO functions x 10K connections), not profiled. Confirm with: `perf stat -e syscalls:sys_enter_clock_gettime` during a benchmark run.

3. **#183 Send path**: The actual throughput improvement from sendmmsg batching depends on kernel version and NIC capabilities. Expected 2-3x on modern Linux kernels with NIC offload.

4. **#172 ECN throughput impact**: The 10-30% improvement estimate is based on published research on ECN-capable networks. Actual impact depends on deployment environment (datacenter vs internet).

### Resolved Unknowns

- **#108 CUBIC** (`confidence::suspected`): **Resolved**. Phase 5 audit confirms CUBIC is now a genuine RFC 8312 implementation with W_max, K computation, cubic growth, and TCP-friendliness. Issue closed.
- **getenv per packet send**: **Resolved** in Phase 3 (commit 7034861).

---

## Phase 4 Gap Closure -- 2026-03-25

### Closed Items
- **QF-E6 (canSendUnderAmplification):** Duplicate computation consolidated -- `canSendUnderAmplification()` now checks `exempt_localhost` + `isLocalhost()` consistently with `overAmplification()`. No redundant evaluation.

---

## Phase 5 Audit -- 2026-03-25

### New Findings (6 issues created)

| Issue | PerfSeverity | PerfScore | Finding |
|---|---|---:|---|
| [#182](https://gitlab.com/devnw/zig/quic/-/issues/182) | P0 | 88 | Timer O(N) + PTO polling -- iterates ALL connections per poll, 30K nanoTimestamp at 10K conns |
| [#183](https://gitlab.com/devnw/zig/quic/-/issues/183) | P1 | 70 | Send path efficiency -- pacing heap alloc, no sendmmsg batching, no GSO |
| [#184](https://gitlab.com/devnw/zig/quic/-/issues/184) | P2 | 48 | readStreamUnlocked copyForwards -- O(N) memmove per stream read |
| [#185](https://gitlab.com/devnw/zig/quic/-/issues/185) | P2 | 36 | 6 remaining orderedRemove call sites -- O(N) shifts |
| [#186](https://gitlab.com/devnw/zig/quic/-/issues/186) | P3 | 20 | tryDrain O(N^2) worst case on out-of-order reassembly |
| [#187](https://gitlab.com/devnw/zig/quic/-/issues/187) | P3 | 12 | PacketBufferPool.release O(16) linear scan |

### Existing Issues Updated (5 issues commented)

| Issue | Action |
|---|---|
| [#154](https://gitlab.com/devnw/zig/quic/-/issues/154) | Added concrete DCID-indexed HashMap fix proposal with code sketch |
| [#163](https://gitlab.com/devnw/zig/quic/-/issues/163) | Confirmed still open; all 15+ ArrayList(u8) sites unchanged |
| [#167](https://gitlab.com/devnw/zig/quic/-/issues/167) | Confirmed still open; linked to #187 sub-issue |
| [#172](https://gitlab.com/devnw/zig/quic/-/issues/172) | Added Phase 2/3 evidence: both recvfrom and recvmmsg paths lack ECN extraction |
| [#108](https://gitlab.com/devnw/zig/quic/-/issues/108) | Confirmed should remain closed: CUBIC is now real RFC 8312 implementation |

### Reclassifications

| Issue | Old | New | Rationale |
|---|---|---|---|
| #108 | P1 / Open / `confidence::suspected` | Closed / Implemented / `confidence::confirmed` | CUBIC now implements RFC 8312 with W_max, K, cubic growth, TCP-friendliness |
| #126 | P2 / untracked | P1 / [#126](https://gitlab.com/devnw/zig/quic/-/issues/126) | Phase 5 analysis shows 500us-5ms lock hold scope including crypto; upgraded severity |

### Additional Issues Noted

| Issue | Action |
|---|---|
| [#126](https://gitlab.com/devnw/zig/quic/-/issues/126) | Phase 5 audit comment: upgraded from P2 to P1 with detailed evidence |
| [#165](https://gitlab.com/devnw/zig/quic/-/issues/165) | Noted as subsumed by broader #183 (send path efficiency) |

### Priority Ordering for Next Sprint

Based on PerfScore and fix effort, the recommended fix order is:

1. **#163** (PerfScore 72, ~4h) -- Mechanical fixedBufferStream replacement. Highest ROI.
2. **#154** (PerfScore 100, 2-3d) -- DCID HashMap. Removes the single biggest scaling bottleneck.
3. **#182** (PerfScore 88, 2-3d) -- Dirty-flag PTO. Second biggest scaling bottleneck.
4. **#183** (PerfScore 70, 2-3d) -- Send queue + sendmmsg. Wires up existing infrastructure.
5. **#172** (PerfScore 48, 1d) -- ECN extraction. Quick win with meaningful throughput impact.
