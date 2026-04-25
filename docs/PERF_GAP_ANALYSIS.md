# Performance Gap Analysis

Last updated: 2026-04-25

GitLab is the source of truth for issue state. This file is the flatfile mirror for performance review findings and closure evidence.

## Summary

- Open / blocked performance issues: 12
- Closed in this pass: 4 (`#184`, `#185`, `#186`, `#187`)
- Baseline checks:
  - `zig build test` exited `0`; the test binary still prints `ERROR: quic_client: connectEx requires a CA certificate (use connectInsecure for insecure testing)`.
  - `zig build -Dtest-filter=stream_edges test` exited `0`.
  - `zig build -Dtest-filter=packet_pool test` exited `0`.
  - `bash -n interop/run_endpoint.sh` exited `0`.
  - `rg -n "orderedRemove" src/quic` returned no matches.
- Workload/SLO inputs remain unknown: target p99 latency, RPS, connection count, datagram rate, stream reorder depth, and deployment ECN support are not documented.

## Stack-Ranked Table

| Rank | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement | GitLab Issue | Fix Summary | Owner | SLA/Due | Status |
|---:|---|---:|---|---|---|---|---|---|---|---|---|
| 1 | P0 | 100 | O(N) connection lookup per packet | endpoint | `src/quic/endpoint/lookup.zig:123-212` scans connection maps for DCID matches | Suspected impact; needs packet-rate benchmark with 1K/10K connections | [#154](https://gitlab.com/devnw/zig/quic/-/issues/154) | Add DCID-indexed lookup table and update CID lifecycle hooks | Endpoint | Strategic | Blocked: requires CID-index design + scale benchmark |
| 2 | P0 | 88 | Timer O(N) + PTO polling per poll cycle | endpoint | `src/quic/endpoint.zig` PTO arming iterates connections per poll | Suspected syscall/CPU impact; confirm with `perf stat` on timer benchmark | [#182](https://gitlab.com/devnw/zig/quic/-/issues/182) | Dirty timer heap or per-connection next-deadline index | Endpoint | Strategic | Blocked: requires timer architecture change + benchmark |
| 3 | P1 | 82 | Endpoint mutex held during receive batch | endpoint | `docs/GAP_ANALYSIS.md` GAP-0053; receive batch processes packets under endpoint mutex | Unmeasured p99 contention; needs concurrent receive benchmark | [#126](https://gitlab.com/devnw/zig/quic/-/issues/126) | Narrow lock scope around lookup/map mutation only | Endpoint | Medium | Blocked: requires concurrency design and regression harness |
| 4 | P1 | 72 | Connection allocations are not broadly pooled | transport | `docs/GAP_ANALYSIS.md` GAP-0054; remaining per-frame `ArrayList(u8)` sites in send/frame paths | Allocation rate not profiled | [#129](https://gitlab.com/devnw/zig/quic/-/issues/129) | Pool packet/frame buffers and replace transient heap buffers | Transport | Medium | Blocked: requires allocator profile and pool ownership design |
| 5 | P1 | 70 | Send path efficiency: pacing heap allocation and no sendmmsg data path | endpoint / transport | `src/quic/endpoint/io.zig`, `src/quic/endpoint.zig`; sendBatch exists but data path remains one packet/syscall | Throughput delta unmeasured | [#183](https://gitlab.com/devnw/zig/quic/-/issues/183) | Queue sends and use sendmmsg/GSO where available | Endpoint | Strategic | Blocked: requires platform-specific batching design |
| 6 | P1 | 64 | 64KB PacketBufferPool per connection | transport | `src/quic/conn.zig` PacketBufferPool still has 16 x 4096-byte slots per connection | Memory model: 64MB per 1K conns, 640MB per 10K conns | [#167](https://gitlab.com/devnw/zig/quic/-/issues/167) | Move to shared/slab pool or lazy allocation | Transport | Medium | Blocked: requires ownership/lifetime redesign |
| 7 | P1 | 56 | ECN bits hardcoded/missing on receive paths | endpoint | `src/quic/endpoint/io.zig`, `src/quic/endpoint/udp_transport.zig` set ECN to zero/null on active recv paths | Deployment impact unknown; needs ECN-capable network test | [#172](https://gitlab.com/devnw/zig/quic/-/issues/172) | Enable recvmsg/recvmmsg cmsg extraction and tests | Endpoint | Medium | Blocked: requires platform matrix validation |
| 8 | P1 | 52 | One syscall per packet send | transport | send batching exists but is not wired into normal data path | Throughput delta unmeasured | [#165](https://gitlab.com/devnw/zig/quic/-/issues/165) | Integrate sendBatch/sendmmsg into transmit path | Transport | Medium | Blocked: overlaps #183 batching design |
| 9 | P1 | 48 | Recovery mutex critical section blocks congestion reads | recovery | `src/quic/recovery/recovery.zig` ACK processing mutates shared recovery state under one lock | Contention unmeasured | [#160](https://gitlab.com/devnw/zig/quic/-/issues/160) | Split immutable cwnd snapshot from mutation path | Recovery | Medium | Blocked: requires recovery concurrency tests |
| 10 | P1 | 44 | Pacing timer truncated to 1ms granularity | endpoint | GitLab issue #158 evidence; high-rate pacing cannot schedule sub-ms sends | Needs high-rate pacing benchmark | [#158](https://gitlab.com/devnw/zig/quic/-/issues/158) | Use nanosecond deadlines and avoid millisecond truncation | Endpoint | Medium | Blocked: requires pacing model tests |
| 11 | P1 | 40 | Double Initial packet encoding | transport | GitLab issue #170 evidence; client Initial can be encoded twice | Needs handshake CPU profile | [#170](https://gitlab.com/devnw/zig/quic/-/issues/170) | Cache encoded Initial or eliminate duplicate path | Transport | Medium | Blocked: requires handshake path audit |
| 12 | P1 | N/A | No STREAM frame coalescing or GSO | transport | `src/quic/connection/methods_b.zig` sends STREAM frames individually | Throughput gap unmeasured | [#109](https://gitlab.com/devnw/zig/quic/-/issues/109) | Coalesce STREAM frames and use GSO where supported | Transport | Strategic | Blocked: requires packetization redesign |

## Findings By Area

### area::app / endpoint

- [#154](https://gitlab.com/devnw/zig/quic/-/issues/154) -- O(N) connection lookup per packet. Blocked on CID-index design and scale benchmark.
- [#182](https://gitlab.com/devnw/zig/quic/-/issues/182) -- Timer O(N) + PTO polling. Blocked on timer architecture change and benchmark.
- [#126](https://gitlab.com/devnw/zig/quic/-/issues/126) -- Endpoint mutex held during receive batch. Blocked on concurrency harness.
- [#183](https://gitlab.com/devnw/zig/quic/-/issues/183) and [#165](https://gitlab.com/devnw/zig/quic/-/issues/165) -- Send batching/GSO not wired into normal data path. Blocked on platform-specific batching design.
- [#172](https://gitlab.com/devnw/zig/quic/-/issues/172) -- ECN extraction missing in active receive paths. Blocked on Linux/macOS behavior validation.
- [#158](https://gitlab.com/devnw/zig/quic/-/issues/158) -- Pacing timer granularity. Blocked on pacing model benchmark.

### area::app / transport

- [#129](https://gitlab.com/devnw/zig/quic/-/issues/129) -- Broad connection allocation pooling remains open.
- [#167](https://gitlab.com/devnw/zig/quic/-/issues/167) -- 64KB PacketBufferPool per connection remains open.
- [#170](https://gitlab.com/devnw/zig/quic/-/issues/170) -- Double Initial encoding remains open.
- [#109](https://gitlab.com/devnw/zig/quic/-/issues/109) -- STREAM coalescing/GSO remains open.
- [#185](https://gitlab.com/devnw/zig/quic/-/issues/185) -- Closed. All `src/quic` `orderedRemove` sites removed; stateless reset token storage now carries explicit sequence numbers before unordered removal.
- [#187](https://gitlab.com/devnw/zig/quic/-/issues/187) -- Closed. `PacketBufferPool.release` computes slot index from pointer offset with bounds/alignment checks.

### area::app / streams

- [#184](https://gitlab.com/devnw/zig/quic/-/issues/184) -- Closed. `StreamRx` now uses `inbox_read_off` and `readInto()` to avoid shifting the inbox on every read.
- [#186](https://gitlab.com/devnw/zig/quic/-/issues/186) -- Closed. `StreamRx.tryDrain()` sorts buffered segments by offset and drains in a single compaction pass.

### area::app / recovery

- [#160](https://gitlab.com/devnw/zig/quic/-/issues/160) -- Recovery mutex critical section remains open and blocked on concurrency tests.

## Quick Wins / Medium / Strategic

### Quick Wins

- Closed: [#186](https://gitlab.com/devnw/zig/quic/-/issues/186), [#187](https://gitlab.com/devnw/zig/quic/-/issues/187).
- Remaining quick wins: none verified. ECN [#172](https://gitlab.com/devnw/zig/quic/-/issues/172) looks small by code size but needs platform validation before closure.

### Medium

- Closed: [#184](https://gitlab.com/devnw/zig/quic/-/issues/184), [#185](https://gitlab.com/devnw/zig/quic/-/issues/185).
- Remaining: [#126](https://gitlab.com/devnw/zig/quic/-/issues/126), [#129](https://gitlab.com/devnw/zig/quic/-/issues/129), [#158](https://gitlab.com/devnw/zig/quic/-/issues/158), [#160](https://gitlab.com/devnw/zig/quic/-/issues/160), [#167](https://gitlab.com/devnw/zig/quic/-/issues/167), [#170](https://gitlab.com/devnw/zig/quic/-/issues/170), [#172](https://gitlab.com/devnw/zig/quic/-/issues/172), [#183](https://gitlab.com/devnw/zig/quic/-/issues/183).

### Strategic

- [#154](https://gitlab.com/devnw/zig/quic/-/issues/154), [#182](https://gitlab.com/devnw/zig/quic/-/issues/182), and [#109](https://gitlab.com/devnw/zig/quic/-/issues/109) require architecture-level changes and scale validation.

## Closed Items

| Issue | Closure evidence |
|---|---|
| [#184](https://gitlab.com/devnw/zig/quic/-/issues/184) | `src/quic/connection/stream.zig` adds `inbox_read_off`/`readInto()`; `methods_b.zig` and `methods_c.zig` use cursor reads; `zig build -Dtest-filter=stream_edges test` passed. |
| [#185](https://gitlab.com/devnw/zig/quic/-/issues/185) | `rg -n "orderedRemove" src/quic` has no matches; `src/quic/conn.zig` stores `ResetTokenEntry{sequence, token}`; `zig build -Dtest-filter=packet_pool test` passed. |
| [#186](https://gitlab.com/devnw/zig/quic/-/issues/186) | `StreamRx.tryDrain()` sorts by offset and drains with one compaction pass; stream reassembly regression passed. |
| [#187](https://gitlab.com/devnw/zig/quic/-/issues/187) | `PacketBufferPool.release()` uses pointer arithmetic instead of a 16-slot scan; source test passed. |

## Blockers And Evidence Needed

- SLOs are Unknown. Need documented latency, throughput, and connection-count targets before prioritizing P0/P1 tradeoffs.
- Workload shape is Unknown. Need expected stream sizes, datagram rates, reorder depth, and connection churn.
- Profiling is incomplete. Need bounded benchmarks/flamegraphs for lookup, timer, send path, and recovery contention.
- `zig build bench` did not complete within a bounded interactive run and was stopped; the benchmark harness needs a documented short profile target for agents.
