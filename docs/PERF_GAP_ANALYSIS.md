# Performance Gap Analysis

Last updated: 2026-04-26

GitLab is the source of truth for issue state. This file is the flatfile mirror for performance review findings and closure evidence.

## Summary

- Active performance issues: 11 (`#109`, `#126`, `#129`, `#154`, `#158`, `#160`, `#165`, `#167`, `#172`, `#182`, `#183`).
- Implemented in this pass: `#170` (double Initial packet encoding). GitLab close/comment is blocked because `glab` has no API token (`glab auth status` returns `401 Unauthorized`).
- Partially implemented but still blocked on benchmark/design proof: `#126`, `#154`, `#158`, `#172`, `#182`.
- Previously closed: `#184`, `#185`, `#186`, `#187`.
- Baseline checks:
  - `zig build test --summary failures` exited `0`; the test binary still prints the known diagnostic `ERROR: quic_client: connectEx requires a CA certificate (use connectInsecure for insecure testing)`.
  - `zig build -Dfull-test-graph=true test --summary failures` exited `0` in the implementation pass.
  - `zig build -Dtest-filter=shortHeaderDcid test --summary failures` exited `0`.
  - `INTEROP_IMPLS=quic-go INTEROP_TESTCASES=http3 make interop-full` exited `0` after the CID latch fix.
  - `make interop-full` exited `0` after final protocol edits: `105` passed, `0` failed, `50` implementation/harness skips.
- Workload/SLO inputs remain unknown: target p99 latency, RPS, connection count, datagram rate, stream reorder depth, and deployment ECN support are not documented.

## Stack-Ranked Table

| Rank | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement | GitLab Issue | Fix Summary | Owner | SLA/Due | Status |
|---:|---|---:|---|---|---|---|---|---|---|---|---|
| 1 | P0 | 100 | O(N) connection lookup per packet | endpoint | `src/quic/endpoint/lookup.zig:138-201` now probes peer+DCID keys and same-peer fallback, but still lacks a full secondary DCID index | Suspected impact; needs packet-rate benchmark with 1K/10K connections | [#154](https://gitlab.com/devnw/zig/quic/-/issues/154) | Add DCID-indexed lookup table and update CID lifecycle hooks | Endpoint | Strategic | Partial / Blocked: fast path improved, full index and benchmark missing |
| 2 | P0 | 88 | Timer O(N) + PTO polling per poll cycle | endpoint | `src/quic/conn.zig:693`; `src/quic/endpoint.zig:876-895` track dirty PTO state, but still iterate active connections to snapshot dirty entries | Suspected syscall/CPU impact; confirm with `perf stat` on timer benchmark | [#182](https://gitlab.com/devnw/zig/quic/-/issues/182) | Dirty timer heap or per-connection next-deadline index | Endpoint | Strategic | Partial / Blocked: dirty flag added, heap/index missing |
| 3 | P1 | 82 | Endpoint receive lock proof incomplete | endpoint | `src/quic/endpoint.zig:848-856` releases endpoint mutex between datagrams | Unmeasured p99 contention; needs concurrent receive benchmark | [#126](https://gitlab.com/devnw/zig/quic/-/issues/126) | Add concurrent receive regression/benchmark | Endpoint | Medium | Partial / Blocked: batch-wide lock removed, proof missing |
| 4 | P1 | 72 | Connection allocations are not broadly pooled | transport | `src/quic/endpoint/server.zig:326-328`; `src/quic/endpoint/server.zig:397-414` allocate/setup connection state per accept | Allocation rate not profiled | [#129](https://gitlab.com/devnw/zig/quic/-/issues/129) | Pool connection/TLS contexts and packet/frame buffers | Transport | Medium | Blocked: requires allocator profile and pool ownership design |
| 5 | P1 | 70 | Send path efficiency: pacing heap allocation and no sendmmsg data path | endpoint / transport | `src/quic/endpoint/udp_transport.zig:300-341` has sendmmsg batch support, but normal sender path still calls per-packet `sendTo` | Throughput delta unmeasured | [#183](https://gitlab.com/devnw/zig/quic/-/issues/183) | Queue sends and use sendmmsg/GSO where available | Endpoint | Strategic | Blocked: requires platform-specific batching design |
| 6 | P1 | 64 | 64KB PacketBufferPool per connection | transport | `src/quic/conn.zig` PacketBufferPool still has 16 x 4096-byte slots per connection | Memory model: 64MB per 1K conns, 640MB per 10K conns | [#167](https://gitlab.com/devnw/zig/quic/-/issues/167) | Move to shared/slab pool or lazy allocation | Transport | Medium | Blocked: requires ownership/lifetime redesign |
| 7 | P1 | 56 | ECN platform validation incomplete | endpoint | `src/quic/endpoint/udp_transport.zig:344-374` and `src/quic/endpoint/udp_transport.zig:443-466` extract ECN cmsg data on Linux; non-Linux fallback remains unverified | Deployment impact unknown; needs ECN-capable network test | [#172](https://gitlab.com/devnw/zig/quic/-/issues/172) | Validate recvmsg/recvmmsg ECN extraction across supported platforms | Endpoint | Medium | Partial / Blocked: Linux active path implemented, platform validation missing |
| 8 | P1 | 52 | One syscall per packet send | transport | `src/quic/endpoint/udp_transport.zig:300-341` implements sendmmsg, but sender integration is not complete | Throughput delta unmeasured | [#165](https://gitlab.com/devnw/zig/quic/-/issues/165) | Integrate sendBatch/sendmmsg into transmit path | Transport | Medium | Blocked: overlaps #183 batching design |
| 9 | P1 | 48 | Recovery mutex critical section blocks congestion reads | recovery | `src/quic/recovery/recovery.zig` ACK processing mutates shared recovery state under one lock | Contention unmeasured | [#160](https://gitlab.com/devnw/zig/quic/-/issues/160) | Split immutable cwnd snapshot from mutation path | Recovery | Medium | Blocked: requires recovery concurrency tests |
| 10 | P1 | 44 | Pacing timer truncated to 1ms granularity | endpoint | `src/quic/endpoint.zig` sends immediately for sub-ms pacing delays, but the timer API remains millisecond based | Needs high-rate pacing benchmark | [#158](https://gitlab.com/devnw/zig/quic/-/issues/158) | Use nanosecond deadlines and avoid millisecond truncation | Endpoint | Medium | Partial / Blocked: sub-ms immediate fast path added, ns timer API missing |
| 11 | P1 | N/A | No STREAM frame coalescing or GSO | transport | `src/quic/connection/methods_b.zig` sends STREAM frames individually | Throughput gap unmeasured | [#109](https://gitlab.com/devnw/zig/quic/-/issues/109) | Coalesce STREAM frames and use GSO where supported | Transport | Strategic | Blocked: requires packetization redesign |

## Findings By Area

### area::app / endpoint

- [#154](https://gitlab.com/devnw/zig/quic/-/issues/154) -- Partially addressed. Lookup now probes peer+DCID keys by candidate DCID length and has a same-peer fallback, but a complete secondary DCID index and scale benchmark are still missing.
- [#182](https://gitlab.com/devnw/zig/quic/-/issues/182) -- Partially addressed. PTO dirty marking reduces needless recomputation, but the endpoint still lacks a min-heap or indexed timer architecture.
- [#126](https://gitlab.com/devnw/zig/quic/-/issues/126) -- Partially addressed. Batch-wide endpoint mutex hold was removed; blocked on a concurrent receive benchmark/regression.
- [#183](https://gitlab.com/devnw/zig/quic/-/issues/183) and [#165](https://gitlab.com/devnw/zig/quic/-/issues/165) -- Send batching/GSO not wired into normal data path. Blocked on platform-specific batching design.
- [#172](https://gitlab.com/devnw/zig/quic/-/issues/172) -- Partially addressed. Active Linux UDP transport now uses `recvmsg`/`recvmmsg` cmsg extraction; blocked on platform matrix validation.
- [#158](https://gitlab.com/devnw/zig/quic/-/issues/158) -- Partially addressed. Sub-ms pacing delays send immediately; blocked on nanosecond timer API and pacing benchmark.

### area::app / transport

- [#129](https://gitlab.com/devnw/zig/quic/-/issues/129) -- Broad connection allocation pooling remains blocked on allocator profile and pool ownership design.
- [#167](https://gitlab.com/devnw/zig/quic/-/issues/167) -- 64KB PacketBufferPool per connection remains blocked on shared/slab lifetime design.
- [#109](https://gitlab.com/devnw/zig/quic/-/issues/109) -- STREAM coalescing/GSO remains blocked on packetization redesign.
- [#170](https://gitlab.com/devnw/zig/quic/-/issues/170) -- Implemented. `sendInitialCrypto` now computes final padded Initial length and encodes once. GitLab closure is blocked by `glab` auth (`401 Unauthorized`).
- [#185](https://gitlab.com/devnw/zig/quic/-/issues/185) -- Closed. All `src/quic` `orderedRemove` sites removed; stateless reset token storage now carries explicit sequence numbers before unordered removal.
- [#187](https://gitlab.com/devnw/zig/quic/-/issues/187) -- Closed. `PacketBufferPool.release` computes slot index from pointer offset with bounds/alignment checks.

### area::app / streams

- [#184](https://gitlab.com/devnw/zig/quic/-/issues/184) -- Closed. `StreamRx` now uses `inbox_read_off` and `readInto()` to avoid shifting the inbox on every read.
- [#186](https://gitlab.com/devnw/zig/quic/-/issues/186) -- Closed. `StreamRx.tryDrain()` sorts buffered segments by offset and drains in a single compaction pass.

### area::app / recovery

- [#160](https://gitlab.com/devnw/zig/quic/-/issues/160) -- Recovery mutex critical section remains blocked on concurrency tests.

## Quick Wins / Medium / Strategic

### Quick Wins

- Closed/implemented in repo: [#186](https://gitlab.com/devnw/zig/quic/-/issues/186), [#187](https://gitlab.com/devnw/zig/quic/-/issues/187), [#170](https://gitlab.com/devnw/zig/quic/-/issues/170). GitLab close for #170 is blocked by missing `glab` API token.
- Remaining quick wins: none verified.

### Medium

- Closed: [#184](https://gitlab.com/devnw/zig/quic/-/issues/184), [#185](https://gitlab.com/devnw/zig/quic/-/issues/185).
- Partial / Blocked: [#126](https://gitlab.com/devnw/zig/quic/-/issues/126), [#158](https://gitlab.com/devnw/zig/quic/-/issues/158), [#172](https://gitlab.com/devnw/zig/quic/-/issues/172).
- Blocked: [#129](https://gitlab.com/devnw/zig/quic/-/issues/129), [#160](https://gitlab.com/devnw/zig/quic/-/issues/160), [#167](https://gitlab.com/devnw/zig/quic/-/issues/167), [#183](https://gitlab.com/devnw/zig/quic/-/issues/183).

### Strategic

- Partial / Blocked: [#154](https://gitlab.com/devnw/zig/quic/-/issues/154), [#182](https://gitlab.com/devnw/zig/quic/-/issues/182).
- Blocked: [#109](https://gitlab.com/devnw/zig/quic/-/issues/109).

## Closed Items

| Issue | Closure evidence |
|---|---|
| [#170](https://gitlab.com/devnw/zig/quic/-/issues/170) | `src/quic/connection/methods_a.zig:268-324` precomputes the final padded Initial protected length and calls `packet.encodeInitialProtected(...)` once; `zig build test --summary failures` passed. GitLab close/comment failed with `401 Unauthorized` because `glab auth status` reports no API token. |
| [#184](https://gitlab.com/devnw/zig/quic/-/issues/184) | `src/quic/connection/stream.zig` adds `inbox_read_off`/`readInto()`; `methods_b.zig` and `methods_c.zig` use cursor reads; `zig build -Dtest-filter=stream_edges test` passed. |
| [#185](https://gitlab.com/devnw/zig/quic/-/issues/185) | `rg -n "orderedRemove" src/quic` has no matches; `src/quic/conn.zig` stores `ResetTokenEntry{sequence, token}`; `zig build -Dtest-filter=packet_pool test` passed. |
| [#186](https://gitlab.com/devnw/zig/quic/-/issues/186) | `StreamRx.tryDrain()` sorts by offset and drains with one compaction pass; stream reassembly regression passed. |
| [#187](https://gitlab.com/devnw/zig/quic/-/issues/187) | `PacketBufferPool.release()` uses pointer arithmetic instead of a 16-slot scan; source test passed. |

## Blockers And Evidence Needed

- SLOs are Unknown. Need documented latency, throughput, and connection-count targets before prioritizing P0/P1 tradeoffs.
- Workload shape is Unknown. Need expected stream sizes, datagram rates, reorder depth, and connection churn.
- Profiling is incomplete. Need bounded benchmarks/flamegraphs for lookup, timer, send path, and recovery contention.
- `zig build bench` did not complete within a bounded interactive run in the original performance review and was stopped; the benchmark harness needs a documented short profile target for agents.
