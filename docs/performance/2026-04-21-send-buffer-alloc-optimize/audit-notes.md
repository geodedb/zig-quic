# Audit notes — `micro/send_buffer_alloc`

- **Session:** `2026-04-21-send-buffer-alloc-optimize`
- **Session state:** `.bench-optimize/session.json`
- **Target bench source:** `benchmarks/micro/send_buffer_alloc.zig`
- **Issue:** [#163](https://gitlab.com/devnw/zig/quic/-/issues/163) — per-frame heap allocation at 15+ sites (P1, PerfScore 72)
- **Zig version:** `0.16.0` (pinned in `build.zig.zon`)
- **HEAD SHA:** `4770a34` (`feat(bench): add micro/send_buffer_alloc to measure #163 send-path heap allocs`)

## 1. Target benchmark

- **Scenario name:** `micro/send_buffer_alloc`
- **Variants (6):** `stream_only`, `stream_plus_ack`, `crypto_handshake`, `initial_padded`, `pto_probe`, `multi_stream_batch`
- **Iterations:** 500 measured × 16-batch = 8000 ops per variant; 100 warmup. (Source: `benchmarks/micro/send_buffer_alloc.zig:323-329`)
- **Registry entry:** `benchmarks/bench_runner.zig:69`

### Native commands

```bash
# Run just the target bench (all 6 variants):
zig build bench -- --suite=send_buffer_alloc --output=/tmp/bench-sba.json

# Run the full micro tier (<30s; includes the target + 8 siblings):
zig build bench-micro --output=/tmp/bench-micro.json

# Variant filter is not exposed; scope via --suite=<short> or --suite=<tier>/<short>.
# Source: benchmarks/bench_runner.zig:82-150 dispatch via matches() on suite arg.
```

### Result schema

- **Field set:** `benchmarks/common.zig:22-58` → `ResultRow`
- **Goal metrics for this session:** `alloc_bytes` (per-op), `alloc_count` (per-op), `throughput_ops_per_sec` (median across repeated runs)
- **Raw samples:** `benchmarks/common.zig:86-100` — `RunOutput.latencies_ns[]` retained as raw per-iteration ns array; aggregated into per-row `latency_p50/p95/p99` + `throughput_stddev_ops_per_sec`
- **Aggregate:** `benchmarks/results/baseline.json` (schema version v2; top-level `rows: []ResultRow`)
- **Note:** baseline.json at `4fda623` does **not** yet contain `micro/send_buffer_alloc` rows. Baseline step must populate.

## 2. Measured code path (production sources that the bench models)

The bench invokes `frame.Frame.write(arrayListWriter)` + `packet.encodeInitialProtected(alloc,…)` with a fresh `std.ArrayList(u8) = .empty` each call. This mirrors these five send-path call sites:

| # | File:line | Call site | Bench variant |
|---|-----------|-----------|---------------|
| 1 | `src/quic/endpoint/handshake_integration.zig:741-781` | Server Initial flight (ServerHello CRYPTO + optional PADDING repad) | `crypto_handshake`, `initial_padded` |
| 2 | `src/quic/endpoint/client.zig:251-346` | Client Initial probe (ClientHello CRYPTO or PING + PADDING to 1200) | `initial_padded` |
| 3 | `src/quic/endpoint/pto.zig:194-232` | PTO probe Initial path (buildInitialProbe + PADDING repad) | `pto_probe` |
| 4 | `src/quic/connection/methods_a.zig:220-294` | `sendInitialCrypto` / `sendHandshakeCrypto` | `crypto_handshake` |
| 5 | `src/quic/packet.zig:509-753` | `encodeInitialProtected` — internal `std.ArrayList(u8) = .empty` at line 522 for the protected output buffer | implicit (all Initial-tier variants) |

Plus encoder twin: `src/quic/packet.zig:754` — `encodeHandshakeProtected` has the same internal `ArrayList(u8) = .empty` pattern.

### Density beyond the 5 hotspots (grep of `src/quic/`)

```
src/quic/connection/methods_b.zig:  26 ArrayList(u8)/arrayListWriter references across 11 distinct send-path assemblies
src/quic/packet.zig:                 11 references
src/quic/connection/methods_a.zig:   11 references
```

`methods_b.zig` sites (grep, all pre-existing): 152, 201, 376, 398, 635, 680, 1053, 1072, 1191, 1228, 1323, 1354, 1486. Each is a per-call `std.ArrayList(u8) = .empty` → `compat.arrayListWriter(&frames, alloc)` → `packet.encode…Protected(…frames.items…)` → free. **Same anti-pattern, same drop-in fix.**

### Helper: `compat.arrayListWriter`

- `src/quic/compat.zig:36` — wraps `std.ArrayList(u8).appendSlice / append / appendNTimes` for each write call
- **Replacement already in-repo:** `src/quic/compat.zig:40-88` — `FixedBufWriter` + `FixedBufStream` + `fixedBufWriter(buf: []u8)` provide stack-buffer writer with identical `writeByte` / `writeAll` / `writeByteNTimes` / `print` surface. **No new API needed; replacement is a pointer-shuffle edit.**

## 3. Dominant metrics expected

| Metric | Expected baseline pattern | Post-fix target |
|--------|---------------------------|-----------------|
| `alloc_bytes` (per-op) | ≥ 1 KiB for Initial-tier variants (1200 B plaintext + encoder `ct_len=payload+16` + ArrayList growth padding); low KiB for `stream_only` / `stream_plus_ack` | `0` for 1-RTT-class variants (stream_only, stream_plus_ack, multi_stream_batch); ≤ one fixed allocation for Initial-tier variants returning owned `[]u8` |
| `alloc_count` (per-op) | `> 0`; several resize-class ArrayList growth events per call (empty → log₂(final_size) doublings) | `0` or `1` |
| `throughput_ops_per_sec` | Noisy; dominated by allocator churn | Modest uplift (alloc-bytes elimination) — bench is alloc-budget gate, not throughput gate |
| `latency_p50/p95/p99_ns` | Tail inflated by ArrayList realloc during growth | Flatter tail |

**Bench framing (source: file header 1-44):** "the bench is shaped as a regression-test gate rather than an absolute upper bound" — i.e. `alloc_bytes` **dropping** is the win, not throughput ops/s. Set `goal_metrics` accordingly.

## 4. Related correctness / integration / stress tests

These must stay green through every iteration (per `optimization-workflow` acceptance criteria). The fix touches Initial/Handshake packet assembly.

### Unit (`zig build test` — fast)

- `tests/unit/endpoint/test_handshake_integration.zig`
- `tests/unit/endpoint/test_client.zig`
- `tests/unit/endpoint/test_server.zig`
- `tests/unit/endpoint/test_pto.zig`
- `tests/unit/endpoint/test_frame_handler.zig`
- `tests/unit/endpoint/test_process_handshake.zig`
- `tests/unit/packet/test_packet.zig`
- `tests/unit/packet/test_header.zig`

### Integration (same test step)

- `tests/test_rfc9001_a1_initial.zig` — RFC 9001 Appendix A.1 test vector (client Initial byte-for-byte)
- `tests/test_rfc9001_a3_server_initial.zig` — RFC 9001 Appendix A.3 (server Initial)
- `tests/test_server_initial_response.zig`
- `tests/test_initial_handshake_loop.zig`
- `tests/test_retry.zig` + `tests/test_retry_tamper.zig`
- `tests/test_initial_crypto_overlap.zig`
- `tests/test_packet_length_varint.zig`
- `tests/test_pto_probe_zero_length_dcid.zig`
- `tests/test_zero_length_scid_coalescing.zig`
- `tests/test_ack_ecn_initial.zig` + `tests/test_ack_ecn_handshake.zig`
- `tests/test_amplification.zig` + `tests/test_nat_rebinding_amplification.zig`

### Adjacent benches (check for collateral regression)

Per session config `adjacent_bench_radius`:
- `micro/frame_serialization` — Frame.write alone (should stay zero-alloc; already zero-alloc)
- `micro/varint` — hot helper called from encoder
- `micro/header_protection` — AEAD-adjacent path
- `integration/handshake_e2e` — end-to-end handshake rate (should benefit)
- `integration/stream_throughput` — 1-RTT send path (should benefit modestly)
- `integration/flush_cadence` — coalesce/flush send path

### Known pre-existing issue (CLAUDE.md)

- `tests/test_transport_geode_compat.zig:246` CA cert runtime assertion — blocks pre-push hook unrelated to this work; use `--no-verify` with explicit user authorization if needed.

## 5. Likely confounders

| Confounder | Mechanism | Mitigation |
|------------|-----------|------------|
| **Allocator freelists warming** | GPA / smp_allocator cache recently-freed blocks; first iteration pays cold, later iterations warm | Bench does 100-iter warmup (`send_buffer_alloc.zig:285-288`) before `CountingAllocator.reset()` |
| **Zig optimize mode drift** | `.Debug` build would change alloc counts vs `.ReleaseFast` | `build.zig` bench steps use optimize option; verify baseline + each iteration use the **same** optimize mode |
| **`BATCH_SIZE=16`** | Per-op normalization `per_op_bytes = alloc_bytes / (N * BATCH_SIZE)` integer-truncates small values; true zero vs sub-batch-level residue is distinguishable only by `alloc_count` / raw `ca.alloc_bytes` | Check both `alloc_bytes` **and** `alloc_count` per op; goal is **both** drop to 0 for 1-RTT variants |
| **`encodeInitialProtected` internal ArrayList** | Even if we fix the 5 outer call sites, the encoder's own `var buf: std.ArrayList(u8) = .empty;` at `packet.zig:522` keeps allocating | Must fix encoder too (same fixed-buffer pattern on a stack-sized ~2 KiB buffer) |
| **PADDING growth via `appendNTimes`** | client Initial 1200-byte pad (`client.zig:328-332`) / PTO (`pto.zig:220`) / server repad (`handshake_integration.zig:770`) trigger ArrayList grow when writing into a dynamic list. Replacement must preallocate enough headroom | Stack buffer sized to 1500 B MTU is safe; grow to `MAX_DATAGRAM_SIZE` if needed |
| **`dupe` of retx buffer** | `client.zig:286` calls `ctx.allocator.dupe(u8, data)` for the retransmit buffer. This is a **semantic** allocation (retx state), not send-buffer churn — **out of scope** for #163 | Do not touch retx / token / pending_initial_packet allocations |
| **CountingAllocator scope** | Hardcoded to count only inside the measured loop (after warmup + reset). It catches `alloc/resize/remap/free` on the counted allocator, not on sub-callees that take the raw parent allocator | The bench passes `counted` through to `runOnce`, which passes it to `frame.Frame.write` and `pkt.encodeInitialProtected` — so both outer and inner ArrayLists are counted. Confirmed. |
| **Median sampling** | `common.runRepeated` runs the bench multiple passes; result row reports median. Tail samples from first pass (if not discarded) could inflate | Bench uses 100 warmup; `common.runRepeated` adds further repetition. Stddev reported separately. |
| **FD exhaustion from neighbors** | `integration/handshake_e2e` 10Kp spawns 10K threads → FD exhaustion can poison subprocess-based env metadata in later scenarios. Not applicable to pure micro tier. | Scope runs to `--suite=send_buffer_alloc` when iterating; only go `--suite=micro` or `--suite=all` for A/B validate. |
| **Micro bench iteration count (500)** | 500 × 16 = 8000 ops — small enough that per-op bytes rounding can skew small-variant results | Cross-check raw `ca.alloc_bytes` / `ca.alloc_calls` totals; the bench only reports per-op truncated values |
| **Harness vs workload scope** | `latencies = allocator.alloc(u64, N)` at `send_buffer_alloc.zig:282` is OUTSIDE the counted scope (explicit comment "keep it OUTSIDE the counting scope"). | Correct as-is; confirmed. |

## 6. Known hot paths & target transform

### Current shape (all 5+ call sites)

```zig
var frames: std.ArrayList(u8) = .empty;              // 1. zero-cap heap list
defer frames.deinit(alloc);                           // 2. free on scope exit
const w = compat.arrayListWriter(&frames, alloc);    // 3. adapter → append/appendSlice
_ = (frame.Frame{ … }).write(w) catch 0;              // 4. grow on each write
… optional appendNTimes(…, PADDING, pad_needed) …    // 5. final growth to 1200 B
const out = packet.encodeInitialProtected(alloc, …, frames.items, keys);
// encodeInitialProtected itself:
//   var buf: std.ArrayList(u8) = .empty;   (packet.zig:522) -- SECOND alloc
//   … grows to header+ciphertext+tag (~1.3 KiB) …
//   returns buf.items (implicit via dupe/toOwnedSlice)
```

### Target shape (`fixed-buffer` drop-in)

```zig
var frame_buf: [1500]u8 = undefined;                  // stack, 0 heap
var fbs = compat.fixedBufWriter(&frame_buf);          // already in-repo
const w = fbs.writer();
_ = (frame.Frame{ … }).write(w) catch 0;
… FixedBufWriter.writeByteNTimes(PADDING, pad_needed) …  // same API, O(1) stack copy
const out = packet.encodeInitialProtected(alloc, …, fbs.getWritten(), keys);
// encodeInitialProtected: convert `var buf: std.ArrayList(u8) = .empty;` path
// to a stack buffer + slice + single `alloc.alloc(u8, final_len)` at return time.
```

### Why this is mechanical

- `ArrayListWriter` and `FixedBufWriter` have identical method sets: `writeByte`, `writeAll`, `writeByteNTimes`, `print` (`compat.zig:14-69`)
- `Frame.write` is already `anytype`-generic and hits zero allocs under fixed buffer (verified by `micro/frame_serialization` baseline which shows `alloc_bytes: 0`)
- `appendNTimes` has a direct analog `writeByteNTimes` on `FixedBufWriter`
- 1500 B stack buffer is safely under the typical Zig default 8 MiB stack

### Risks

1. **Writer API surface drift** — if any call site uses `list.items.len`, `list.appendSlice` directly, or other `ArrayList` methods beyond the writer adapter, it needs adjustment. Grep confirms mostly `.items` reads (fine via `fbs.getWritten()`) and some direct `appendNTimes` (replaceable via `FixedBufWriter.writeByteNTimes`).
2. **`encodeInitialProtected` / `encodeHandshakeProtected` return `[]u8`** — callers free the return with `alloc.free(out)`. The encoder must still perform **one** owned allocation at the end (for ciphertext + header concat). This is by design; #163 is about eliminating **per-frame churn**, not the one owned output allocation.
3. **Size cap** — 1200 B Initial + 1.4 KiB protected wrap means ~1500 B fits. If any path ever exceeds 1500 B (jumbo datagram, large retry token), we need either a bigger stack cap or a graceful fallback. PTO / Initial pathway is RFC-capped; 1-RTT stream path is dgram-MTU-capped.

## Next step

`/bench-optimize:baseline` — reproduce the bench in isolation from a clean build at HEAD (`4770a34`), capture per-variant `alloc_bytes` / `alloc_count` / latency distribution, store aggregate JSON under `docs/performance/2026-04-21-send-buffer-alloc-optimize/baseline/`.
