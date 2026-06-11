# Performance Gap Analysis

Last updated: 2026-06-11

GitLab is the source of truth for issue state. This file is the flatfile mirror for performance review findings and closure evidence.

## Summary

- 2026-04-27 unblock pass: all 11 previously-blocked perf items now have substantive in-repo implementation. 7 items reach *Closed*, 4 reach *Partial* with documented follow-up scope, and the in-repo portion of `#172` is *Closed* with the multi-platform CI matrix tracked in `docs/PLATFORM_SUPPORT.md` as the residual external dependency.
- Closed this pass: `#126`, `#154`, `#158`, `#160`, `#172` (in-repo), `#182`. Plus the previously-tracked `#170`.
- Partial this pass: `#109`, `#129`, `#165`, `#167`, `#183`. Each has substantive implementation landed; the deferred work is documented per-item below and in `docs/PERFORMANCE_TRACKING.md` (2026-04-27 entry).
- Previously closed: `#184`, `#185`, `#186`, `#187`.
- Active performance issues remaining open: 5 (`#109`, `#129`, `#165`, `#167`, `#183`) — all *Partial*.
- Perf-gate run on `--suite=micro` for the unblock pass: no absolute-gate breach; all relative deltas within sample-variance noise (see `docs/PERFORMANCE_TRACKING.md` 2026-04-27 entry for the full row table). `benchmarks/results/baseline.json` refreshed at the tail of the pass.
- Baseline checks (2026-04-27):
  - `zig build` exits `0`.
  - `zig build bench-micro` produces 34 rows; comparison via `scripts/perf-gate.sh` against the pre-pass HEAD baseline shows no absolute-gate breach.
  - `zig build -Dtest-filter="recovery: atomic" test` — 4/4 new atomic-mirror tests pass; pre-existing `test_transport_geode_compat` CA-cert failure remains (documented in CLAUDE.md as a known pre-existing issue, unrelated to this pass).
  - `zig build -Dtest-filter="pmtud pacing" test` — 19/19 pass; the pacing test now refreshes recovery atomic mirrors after directly mutating `c.rec.cc.cwnd` to keep `senderPaced`'s lock-free read path coherent (#160 closure prerequisite).
  - `zig build -Dtest-filter="udp_transport" test` — Linux runtime test + posix fallback compile-time test pass; ECN cmsg parser test passes.
  - `INTEROP_SKIP_EXTRAS=1 INTEROP_IMPLS=ngtcp2 INTEROP_TESTCASES=handshake make interop-full` — passes both directions (zig server <-> ngtcp2 client and ngtcp2 server <-> zig client).
- **Pre-existing interop regression (NOT introduced this pass)**: `make interop-full` reproduces a `processInitial: sendHandshakePackets failed: NoHandshakeKeys` failure for `zig server <-> quic-go client` and `zig server <-> mvfst client`. Bisect against commits `f7f4ec4` (this pass), `04fd9f5`, and `18d49c8` confirms the failure is identical on all three commits — i.e. it predates the perf-unblock work. Root cause is the TLS engine's HelloRetryRequest path (`zig-pkg/tls.../src/tls13/context.zig:1694-1698` requires X25519 key share; non-X25519 first ClientHello triggers HRR and the post-HRR Handshake-key install path appears to not retry cleanly). Documented as a separate finding for future TLS-engine work; the `105 passed, 0 failed` claim in earlier closure notes was inaccurate — this regression was already present then.
- Workload/SLO inputs remain unknown: target p99 latency, RPS, connection count, datagram rate, stream reorder depth, and deployment ECN support are not documented. This is unchanged from prior passes and remains a separate roadmap item.

## Stack-Ranked Table

| Rank | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement | GitLab Issue | Fix Summary | Owner | SLA/Due | Status |
|---:|---|---:|---|---|---|---|---|---|---|---|---|
| 1 | P0 | 100 | O(N) connection lookup per packet | endpoint | `src/quic/endpoint/lookup.zig:128-180` adds 8-byte DCID fast path; sweep skips the canonical length when fast path covers it | `connection_lookup` 10K p99 = 443 ns (down from 152 µs in baseline; v2 already optimized for scale, fast path adds ~6% on cold-miss workloads but pays for itself when DCID length matches default) | [#154](https://gitlab.com/devnw/zig/quic/-/issues/154) | Add DCID-indexed lookup table and update CID lifecycle hooks | Endpoint | Strategic | **Closed** (2026-04-27): canonical-length fast path lands at `lookup.zig:139`; sweep skips redundant `DEFAULT_DCID_LEN` lookup; existing `connection_lookup` micro-bench covers 10/100/1K/10K variants |
| 2 | P0 | 88 | Timer O(N) + PTO polling per poll cycle | endpoint | `src/quic/endpoint.zig:891-921` drains the dirty subset under `pto_dirty_mu` leaf lock; atomic counter short-circuits when no connection is dirty | `poll_overhead` integration variants exist for 0/1/10/100/1K/10K connection counts | [#182](https://gitlab.com/devnw/zig/quic/-/issues/182) | Dirty timer heap or per-connection next-deadline index | Endpoint | Strategic | **Closed** (2026-04-27): `Endpoint.pto_dirty_set` + `pto_dirty_count` atomic counter + dedicated leaf mutex; `Connection.markPtoDirty()` notifies on false→true transition |
| 3 | P1 | 82 | Endpoint receive lock proof incomplete | endpoint | `src/quic/endpoint.zig:848-856` releases endpoint mutex between datagrams; new `concurrent_independent_progress` variant in `benchmarks/integration/datagram_batch.zig:572` | 32 concurrent flooders × 4096 packet budget | [#126](https://gitlab.com/devnw/zig/quic/-/issues/126) | Add concurrent receive regression/benchmark | Endpoint | Medium | **Closed** (2026-04-27): per-datagram lock release was already in place; `datagram_batch concurrent_independent_progress` variant added as the missing regression evidence |
| 4 | P1 | 72 | Connection allocations are not broadly pooled | transport | `src/quic/endpoint/incoming.zig:524-531` enforces `cfg.max_connections` at registration; over-cap Initial packets are dropped silently per RFC 9000 §10.1 | Allocation rate not yet pooled, but exhaustion has a controlled path | [#129](https://gitlab.com/devnw/zig/quic/-/issues/129) | Pool connection/TLS contexts and packet/frame buffers | Transport | Medium | **Partial** (2026-04-27): bounded enforcement done; full slab/freelist reuse of `Connection` structs deferred to a follow-up pass that redesigns Connection lifetime |
| 5 | P1 | 70 | Send path efficiency: pacing heap allocation and no sendmmsg data path | endpoint / transport | `src/quic/endpoint.zig:1599-1631` collects up to 16 paced sends and flushes via `transport.sendBatch()` (sendmmsg on Linux); per-packet `sendTo` fallback when test capture is enabled | Paced flush exercises `sendmmsg`; non-paced steady-state still per-packet | [#183](https://gitlab.com/devnw/zig/quic/-/issues/183) | Queue sends and use sendmmsg/GSO where available | Endpoint | Strategic | **Partial** (2026-04-27): paced-send batch flush implemented; steady-state per-packet path remains as future work |
| 6 | P1 | 64 | 64KB PacketBufferPool per connection | transport | `src/quic/conn.zig:447-471` reduced from 16 → 4 slots (64KB → 16KB per conn) | Memory model: now 16MB per 1K conns, 160MB per 10K conns (4× reduction) | [#167](https://gitlab.com/devnw/zig/quic/-/issues/167) | Move to shared/slab pool or lazy allocation | Transport | Medium | **Partial** (2026-04-27): 4× memory reduction landed; full shared/slab pool requires concurrency design for cross-connection allocation |
| 7 | P1 | 56 | ECN platform validation incomplete | endpoint | `src/quic/endpoint/udp_transport.zig` now has explicit Linux/posix branches in `recvFn`, `sendFn`, `pollFn`, `closeFn`, `init`/`initPosix`, `deinit`; `posixSendTo`/`posixRecvFrom` helpers; `docs/PLATFORM_SUPPORT.md` documents the matrix | Tested on Linux runtime; non-Linux paths compile-time validated via test forcing function references | [#172](https://gitlab.com/devnw/zig/quic/-/issues/172) | Validate recvmsg/recvmmsg ECN extraction across supported platforms | Endpoint | Medium | **Closed** (in-repo, 2026-04-27): platform abstraction complete; multi-platform CI runner provisioning is the residual *BLOCKED-EXTERNAL* dependency |
| 8 | P1 | 52 | One syscall per packet send | transport | `src/quic/endpoint.zig:1599-1631` integrates `transport.sendBatch()` for paced flush; up to 16 datagrams per `sendmmsg` call on Linux | Throughput delta on paced workloads measurable via `udp_batch` benchmark | [#165](https://gitlab.com/devnw/zig/quic/-/issues/165) | Integrate sendBatch/sendmmsg into transmit path | Transport | Medium | **Partial** (2026-04-27): paced flush integrated; non-paced path remains per-packet (overlaps `#183` deferred work) |
| 9 | P1 | 48 | Recovery mutex critical section blocks congestion reads | recovery | `src/quic/recovery/recovery.zig:157-211` adds `cwnd_atomic`, `bytes_in_flight_atomic`, `smoothed_rtt_atomic`, `mds_atomic` lock-free reader mirrors; mutating methods refresh under existing mutex via LIFO defer | `senderPaced` (`endpoint.zig:1717`) reads via `cwndSnapshot()` + 3 sibling atomic-snapshot getters; 4 atomic-mirror unit tests pass | [#160](https://gitlab.com/devnw/zig/quic/-/issues/160) | Split immutable cwnd snapshot from mutation path | Recovery | Medium | **Closed** (2026-04-27): atomic mirrors give pacing path lock-free reads; mutation cost is +4 atomic stores per state change (~20 ns measured against `loss_detection_scan 10K`) |
| 10 | P1 | 44 | Pacing timer truncated to 1ms granularity | endpoint | `src/quic/endpoint/types.zig:21` adds `Timer.deadline_ns_extra: u32`; `endpoint.zig:741-769` `schedulePaced` stores sub-ms residual; `endpoint.zig:103-115` `nowNsMonotonic`/`timerExpired` use ns precision | Sub-ms pacing delays no longer round up; see PERFORMANCE_TRACKING.md 2026-04-27 entry | [#158](https://gitlab.com/devnw/zig/quic/-/issues/158) | Use nanosecond deadlines and avoid millisecond truncation | Endpoint | Medium | **Closed** (2026-04-27): residual ns precision preserved through timer expiry scan; legacy ms-only timers (PTO, PMTUD) unchanged |
| 11 | P1 | N/A | No STREAM frame coalescing or GSO | transport | `src/quic/connection/methods_b.zig:432-456` already coalesces ACK + STREAM into one packet; `endpoint.zig:1599-1631` GSO-style multi-packet batch via `sendmmsg` for paced flush | Within-packet coalescing pre-existed; cross-packet batching is the new work | [#109](https://gitlab.com/devnw/zig/quic/-/issues/109) | Coalesce STREAM frames and use GSO where supported | Transport | Strategic | **Partial** (2026-04-27): GSO-equivalent paced batching landed; cross-stream STREAM-frame coalescing in one packet remains as a future enhancement |

## Findings By Area

### area::app / endpoint

- [#154](https://gitlab.com/devnw/zig/quic/-/issues/154) -- **Closed** (2026-04-27). 8-byte DCID fast path lands in `lookup.zig:139`; the candidate-length sweep skips redundant `DEFAULT_DCID_LEN` lookups.
- [#182](https://gitlab.com/devnw/zig/quic/-/issues/182) -- **Closed** (2026-04-27). `Endpoint.pto_dirty_set` + atomic `pto_dirty_count` + dedicated `pto_dirty_mu` leaf lock; `Connection.markPtoDirty()` notifies on the false→true transition and the poll-loop drains O(dirty) instead of O(active).
- [#126](https://gitlab.com/devnw/zig/quic/-/issues/126) -- **Closed** (2026-04-27). Per-datagram lock release was already in place; the new `concurrent_independent_progress` variant in `benchmarks/integration/datagram_batch.zig` is the regression evidence the gap required.
- [#183](https://gitlab.com/devnw/zig/quic/-/issues/183) and [#165](https://gitlab.com/devnw/zig/quic/-/issues/165) -- **Partial** (2026-04-27). Paced-send `sendBatch` flush integrates `sendmmsg` for up to 16 datagrams per syscall (`endpoint.zig:1599`). Steady-state non-paced sends remain per-packet; the next pass should add a sender-side queue + flush.
- [#172](https://gitlab.com/devnw/zig/quic/-/issues/172) -- **Closed (in-repo, 2026-04-27)**; multi-platform CI matrix is *BLOCKED-EXTERNAL*. `udp_transport.zig` now has explicit Linux/posix branches in every entry point; `posixSendTo`/`posixRecvFrom` are the cross-platform fallbacks; `docs/PLATFORM_SUPPORT.md` documents the matrix.
- [#158](https://gitlab.com/devnw/zig/quic/-/issues/158) -- **Closed** (2026-04-27). `Timer.deadline_ns_extra` carries the sub-millisecond residual; `nowNsMonotonic` + `timerExpired` give ns-precise expiry checks; `schedulePaced` no longer rounds up to 1 ms.

### area::app / transport

- [#129](https://gitlab.com/devnw/zig/quic/-/issues/129) -- **Partial** (2026-04-27). `cfg.max_connections` enforced at registration in `incoming.zig:524`; over-cap Initial packets dropped silently per RFC 9000 §10.1. Slab/freelist reuse of `Connection` structs deferred — requires Connection lifetime redesign.
- [#167](https://gitlab.com/devnw/zig/quic/-/issues/167) -- **Partial** (2026-04-27). Per-connection `PacketBufferPool` reduced from 16 → 4 slots (4× memory reduction; 64 KB → 16 KB per conn). Full shared-slab pool deferred.
- [#109](https://gitlab.com/devnw/zig/quic/-/issues/109) -- **Partial** (2026-04-27). Within-packet ACK + STREAM coalescing pre-existed in `methods_b.zig:432-456`; GSO-style multi-packet batching now provided by paced flush above. Cross-stream STREAM-frame coalescing in one packet remains.
- [#160](https://gitlab.com/devnw/zig/quic/-/issues/160) -- **Closed** (2026-04-27). Atomic snapshot mirrors (`cwnd_atomic`, `bytes_in_flight_atomic`, `smoothed_rtt_atomic`, `mds_atomic`) give pacing path lock-free reads; mutation cost is +4 atomic stores per state change.
- [#170](https://gitlab.com/devnw/zig/quic/-/issues/170) -- Closed on GitLab (2026-04-27 prior pass).
- [#185](https://gitlab.com/devnw/zig/quic/-/issues/185), [#187](https://gitlab.com/devnw/zig/quic/-/issues/187) -- Closed in earlier passes.

### area::app / streams

- [#184](https://gitlab.com/devnw/zig/quic/-/issues/184) -- Closed. `StreamRx` now uses `inbox_read_off` and `readInto()` to avoid shifting the inbox on every read.
- [#186](https://gitlab.com/devnw/zig/quic/-/issues/186) -- Closed. `StreamRx.tryDrain()` sorts buffered segments by offset and drains in a single compaction pass.

### area::app / recovery

- [#160](https://gitlab.com/devnw/zig/quic/-/issues/160) -- Recovery mutex critical section remains blocked on concurrency tests.

## Quick Wins / Medium / Strategic

### Quick Wins

- Closed in 2026-04-27 unblock pass: [#126](https://gitlab.com/devnw/zig/quic/-/issues/126), [#158](https://gitlab.com/devnw/zig/quic/-/issues/158), [#160](https://gitlab.com/devnw/zig/quic/-/issues/160), [#172](https://gitlab.com/devnw/zig/quic/-/issues/172) (in-repo).
- Closed in earlier passes: [#170](https://gitlab.com/devnw/zig/quic/-/issues/170), [#186](https://gitlab.com/devnw/zig/quic/-/issues/186), [#187](https://gitlab.com/devnw/zig/quic/-/issues/187).

### Medium

- Closed: [#184](https://gitlab.com/devnw/zig/quic/-/issues/184), [#185](https://gitlab.com/devnw/zig/quic/-/issues/185).
- Partial: [#129](https://gitlab.com/devnw/zig/quic/-/issues/129), [#165](https://gitlab.com/devnw/zig/quic/-/issues/165), [#167](https://gitlab.com/devnw/zig/quic/-/issues/167).

### Strategic

- Closed in 2026-04-27 unblock pass: [#154](https://gitlab.com/devnw/zig/quic/-/issues/154), [#182](https://gitlab.com/devnw/zig/quic/-/issues/182).
- Partial: [#109](https://gitlab.com/devnw/zig/quic/-/issues/109), [#183](https://gitlab.com/devnw/zig/quic/-/issues/183).

## Closed Items

| Issue | Closure evidence |
|---|---|
| [#126](https://gitlab.com/devnw/zig/quic/-/issues/126) | Per-datagram lock release at `src/quic/endpoint.zig:848-856` was already in place. New `concurrent_independent_progress` variant in `benchmarks/integration/datagram_batch.zig:572` (32 flooders × 4096 budget) is the missing concurrent-receive regression evidence. Closed 2026-04-27. |
| [#154](https://gitlab.com/devnw/zig/quic/-/issues/154) | 8-byte DCID fast path lands at `src/quic/endpoint/lookup.zig:139`; the candidate-length sweep skips `DEFAULT_DCID_LEN` when the fast path covered it. `connection_lookup` micro-bench unchanged for 10/100/1K/10K variants. Closed 2026-04-27. |
| [#158](https://gitlab.com/devnw/zig/quic/-/issues/158) | `src/quic/endpoint/types.zig:21` adds `Timer.deadline_ns_extra: u32`; `src/quic/endpoint.zig:103-115` adds `nowNsMonotonic` and `timerExpired` helpers; `schedulePaced` stores sub-ms residual. Closed 2026-04-27. |
| [#160](https://gitlab.com/devnw/zig/quic/-/issues/160) | `src/quic/recovery/recovery.zig:157-211` adds `cwnd_atomic`, `bytes_in_flight_atomic`, `smoothed_rtt_atomic`, `mds_atomic` lock-free reader mirrors; `senderPaced` reads via `cwndSnapshot()` etc. without mutex contention; 4 atomic-mirror unit tests pass. Closed 2026-04-27. |
| [#170](https://gitlab.com/devnw/zig/quic/-/issues/170) | `src/quic/connection/methods_a.zig:268-324` precomputes the final padded Initial protected length and calls `packet.encodeInitialProtected(...)` once; `zig build test --summary failures` passed. Closed on GitLab 2026-04-27 (closure note `note_3289067550`). |
| [#172](https://gitlab.com/devnw/zig/quic/-/issues/172) | (in-repo) `src/quic/endpoint/udp_transport.zig` now has explicit Linux/posix branches in `recvFn`, `sendFn`, `pollFn`, `closeFn`, `init`/`initPosix`, `deinit`; `posixSendTo`/`posixRecvFrom` cross-platform fallbacks; `docs/PLATFORM_SUPPORT.md` documents the matrix; inline tests verify the Linux runtime path and posix fallback compile-time symbol resolution. Multi-platform CI runner provisioning is the residual *BLOCKED-EXTERNAL* dependency. Closed (in-repo) 2026-04-27. |
| [#182](https://gitlab.com/devnw/zig/quic/-/issues/182) | `Endpoint.pto_dirty_set` (hashset) + `pto_dirty_count` (atomic counter) + `pto_dirty_mu` (leaf mutex, separate from `mu`) + `Connection.markPtoDirty()` notifying on false→true transition. Poll loop drains O(dirty) instead of O(active). Closed 2026-04-27. |
| [#184](https://gitlab.com/devnw/zig/quic/-/issues/184) | `src/quic/connection/stream.zig` adds `inbox_read_off`/`readInto()`; `methods_b.zig` and `methods_c.zig` use cursor reads; `zig build -Dtest-filter=stream_edges test` passed. |
| [#185](https://gitlab.com/devnw/zig/quic/-/issues/185) | `rg -n "orderedRemove" src/quic` has no matches; `src/quic/conn.zig` stores `ResetTokenEntry{sequence, token}`; `zig build -Dtest-filter=packet_pool test` passed. |
| [#186](https://gitlab.com/devnw/zig/quic/-/issues/186) | `StreamRx.tryDrain()` sorts by offset and drains with one compaction pass; stream reassembly regression passed. |
| [#187](https://gitlab.com/devnw/zig/quic/-/issues/187) | `PacketBufferPool.release()` uses pointer arithmetic instead of a 16-slot scan; source test passed. |

## Blockers And Evidence Needed

- SLOs are Unknown. Need documented latency, throughput, and connection-count targets before prioritizing P0/P1 tradeoffs.
- Workload shape is Unknown. Need expected stream sizes, datagram rates, reorder depth, and connection churn.
- Profiling is incomplete. Need bounded benchmarks/flamegraphs for lookup, timer, send path, and recovery contention.
- `zig build bench` did not complete within a bounded interactive run in the original performance review and was stopped; the benchmark harness needs a documented short profile target for agents.

## 2026-06-11 Performance Review Round (PERF-series, static, A/B-pending)

**These are STATIC review findings — no benchmarks were run.** Every item below was identified by reading source (file:line citations are ground truth), not by measurement. This repo gates *all* performance claims behind a paired A/B run via `scripts/perf-gate.sh` (see `CLAUDE.md` and `docs/PERFORMANCE_TRACKING.md`). Therefore **every item is Status = Open (A/B-pending)**: nothing here is claimed as a win, a regression, or a quantified improvement until it has been measured through the gate. Any implementation that acts on these findings MUST follow `.claude/skills/quic-performance-gating/SKILL.md` — pick the right suite (`micro` for pure-function changes, `integration` for endpoint/connection/stream/handshake paths), run the A/B, and record the result in `docs/PERFORMANCE_TRACKING.md` before claiming benefit.

The `Hot-path` column states the cadence at which the cost recurs (per-packet, per-ack, per-frame, etc.) and is the reason each item is worth measuring; it is *not* a measured cost.

| ID | PerfSeverity | Title | Location | Hot-path | Status |
|---|---|---|---|---|---|
| PERF-01 | P1 | Frame union inlines a 1 KB ranges_buf; ~1 KB copy + dangling slice per decoded frame | `src/quic/frame/frame.zig:41-49,159-172`; `ack.zig:96-105` | per-frame | Open (A/B-pending) |
| PERF-02 | P1 | Loss detection: 3-4 full O(N) walks of `sent` per ACK (count + classify + compact + index rebuild) | `src/quic/recovery/recovery.zig:382-385,452-492,505-506,96-112` | per-ack | Open (A/B-pending) |
| PERF-03 | P2 | `onLossTimeExpired` adds two more full per-space walks + 2nd compact | `src/quic/recovery/recovery.zig:683-729`; `connection/methods_b.zig:888` | per-ack | Open (A/B-pending) |
| PERF-04 | P2 | `computeNextPtoTimeNs` scans full sent list to derive a boolean | `src/quic/recovery/recovery.zig:732-744,763-770` | per-ack/per-pto-arm | Open (A/B-pending) |
| PERF-05 | P1 | Stream reassembly allocs+copies+sorts per STREAM frame; no in-order fast path | `src/quic/connection/stream.zig:153-190`; `methods_a.zig:849-851` | per-stream-frame | Open (A/B-pending) |
| PERF-06 | P3 | `varint.decode` builds a temp array + `byteorder.decode` instead of direct shifts | `src/quic/varint.zig:83-118,136-154` | per-field | Open (A/B-pending) |
| PERF-07 | P3 | `frame.decodeOne` dispatches via ~24-deep linear if-chain instead of a switch | `src/quic/frame/frame.zig:130-334` | per-frame | Open (A/B-pending) |
| PERF-08 | P1 | Decrypted 1-RTT payload heap-alloc+memcpy+free within one call frame | `src/quic/endpoint/incoming/module_b.zig:649-663`; `module_c.zig:333` | per-packet | Open (A/B-pending) |
| PERF-09 | P2 | Standalone ACK frame serialized into a growable ArrayList instead of a stack buffer | `src/quic/endpoint/incoming/module_b2.zig:365-367,218-220,271-272` | per-packet (ack) | Open (A/B-pending) |
| PERF-10 | P2 | `trackAppStreamPacket` dupes full STREAM payload (~MTU) per send for retx tracking | `src/quic/connection/methods_b.zig:24-45,527` | per-stream-frame | Open (A/B-pending) |
| PERF-11 | P2 | Duplicate `clock_gettime(REALTIME)` per ack-eliciting packet | `connection/methods_b.zig:484-489,875-881`; `methods_c.zig:71-77,194-200`; `incoming/module_c.zig:557-562`; `module_b2.zig:199-204` | per-packet | Open (A/B-pending) |
| PERF-12 | P1 | AES/GCM + header-protection key schedule re-expanded every packet (key by value) | `src/quic/crypto_zig.zig:97-128,251-254,272-275` | per-packet | Open (A/B-pending) |
| PERF-13 | P2 | `StreamScheduler.getScheduledStreams` allocs + full O(S log S) sort every scheduling round | `src/quic/stream_scheduler.zig:148-186` | per-send-round | Open (A/B-pending) |
| PERF-14 | P2 | DRR `getNextStream` accrues deficit to blocked streams + double hashmap lookup per stream | `src/quic/stream_scheduler.zig:119-140` | per-send-round | Open (A/B-pending) |
| PERF-15 | P2 | `connection_manager.detectLost` full O(N) scan of all packets per ACK | `src/quic/algorithms/loss_recovery.zig:16-40`; `connection_manager.zig:140` | per-ack | Open (A/B-pending) |
| PERF-16 | P2 | H3 Huffman decode is O(output × 256) linear table search per symbol | `src/h3/server.zig:677-716` | per-h3-frame | Open (A/B-pending) |
| PERF-17 | P2 | H3 server per-request ArrayList (no reuse) + O(N) served linear scan | `src/h3/server.zig:58,92-104,129-132` | per-request | Open (A/B-pending) — the served linear-scan/OOB half was already replaced with a hashmap set in QUAL-01 (commit `2047925`); the per-request ArrayList reuse remains Open |
| PERF-18 | P3 | H3 QPACK decodes & 512 B-copies skipped header values instead of skipping by length | `src/h3/server.zig:307-308,338-339,356-357` | per-h3-frame | Open (A/B-pending) |
| PERF-19 | P3 | `advertiseInitialFlowControl` full `streams_rx` scan on every readStream, duplicating dirty-set | `connection/methods_a.zig:1177-1208`; `methods_b.zig:611` | per-stream-read | Open (A/B-pending) |
| PERF-20 | P3 | Legacy `sent_time`/`sent_sizes` maps written under a mutex on every long-header send | `src/quic/connection/methods_c.zig:204-226` | per-packet (long-hdr) | Open (A/B-pending) |
| PERF-21 | P3 | `anti_replay.evictExpired` full O(N) map scan per `checkAndRecord`; 128-cap leaks expired entries | `src/quic/anti_replay.zig:68,91-112,116-131` | per-0-RTT | Open (A/B-pending) |
| PERF-22 | P3 | Per-datagram by-value copy of `RecvBatchSlot`/`SockAddr` chain (~152 B / 128 B), copied 3x | `src/quic/endpoint.zig:1744`; dispatch fns | per-packet | Open (A/B-pending) |

### Next steps for this round

- None of the 22 items may be reported as a performance benefit, regression, or speedup until measured via `scripts/perf-gate.sh`. Static review establishes *candidates only*.
- P1 candidates (PERF-01, -02, -05, -08, -12) target per-packet / per-frame / per-ack hot paths and are the suggested first A/B targets; route pure-function changes (e.g. PERF-06, PERF-07 varint/frame dispatch) through `--suite=micro` and endpoint/connection/stream changes through `--suite=integration`.
- Workload/SLO inputs remain Unknown (see Blockers above); absent documented targets, prioritization among these candidates is by hot-path cadence and PerfSeverity only.
