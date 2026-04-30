# BUG: Long Server-Initiated Response Stream Stalls Mid-Transfer

**Status:** RESOLVED 2026-04-30 — root cause was a 4-byte DCID truncation
in the deferred / immediate ECN-ACK emit paths
(`src/quic/endpoint/incoming/module_b2.zig`). Once the receiver's ECN
flag fired, every standalone ACK packet was emitted with a 4-byte DCID
that did not match the peer's full 8-byte `our_scid`, so
`localDcidMatchLen` rejected the packet and the sender's recovery layer
never advanced `largest_acked`. With ACK feedback dropped, cwnd stayed
pinned at the initial 10×MDS value and `bytes_in_flight >= cwnd` blocked
every subsequent `writeStream` call. Fix: emit the full peer-initial
SCID on those two paths, matching what the normal-ACK and ACK-only
paths already did. Regression test:
`tests/test_long_response_stream_stall.zig`, registered in the default
`zig build test` graph (not gated on `--full-test-graph`).
**Filed:** 2026-04-29
**Affected library version:** `gitlab.com/devnw/zig/quic` HEAD as of `d6b60890e7440fd14ac6a1d03484ad9bcb1e6f0a`
**Discovered via:** Geode database integration suite — specs `gap_0257_orderby_large_resultset.yml` and `transaction_chunked_execution.yml`

---

## Symptom

Server emits a sequence of length-prefixed protobuf messages on a single
bidirectional QUIC stream (typical pattern: one schema + N data pages + one
final page with a "done" flag). The client opens the stream, reads the first
several messages successfully, then **stops receiving further messages even
though the server has more pending data and neither side has signalled FIN
or stream error**.

From the client's perspective:

- Reads succeed for the first M messages (M is non-zero — schema and
  several data pages arrive correctly with their payload intact).
- After message M, `quic.readStream` returns 0 / `WouldBlock` indefinitely.
- No `MAX_STREAM_DATA` frame is ever issued by either side that explains
  the halt.
- No FIN, RESET_STREAM, or CONNECTION_CLOSE frame arrives.
- The client eventually exits its read loop on application-level timeout
  (e.g., `--timeout 30` in the geode CLI), reporting the partial result it
  managed to accumulate.

From the server's perspective:

- `stream.writeAll(...)` calls all return successfully (no
  `FlowControlBlocked`, no `WriteError`).
- The connection's exposed metrics show
  `quic_total_bytes_in_flight ≈ quic_total_cwnd_bytes ≈ 12_411` bytes
  pinned for the duration of the stall — i.e. cwnd never grows past the
  initial window even though the loopback RTT is well under 1 ms and the
  client is actively polling.
- `quic_min_flow_control_headroom ≈ 268_421_998` (256 MiB) — connection-
  level flow control is **not** the limiting factor.

---

## Reproduction (deterministic)

The bug is reproducible **on loopback** with a single client and a single
server, using stock geode + geode-client-zig:

### Setup

```bash
# 1. Build geode at HEAD that pins quic@d6b60890.
cd ~/src/devnw/codepros/geode/geode
zig build -Dotel_use_devnw_tls=true

# 2. Spawn an isolated geode server on a free port.
PORT=53142
DATA_DIR=$(mktemp -d /tmp/geode-perftest-XXXX)
GEODE_ADMIN_PASSWORD='Test_Admin_Pass_Word_2026!' \
  ./zig-out/bin/geode serve \
    --data-dir "$DATA_DIR" \
    --listen "127.0.0.1:$PORT" \
    --insecure \
    --log-level error &

# 3. Seed 1000 nodes (20 batches of 50).
PASS='Test_Admin_Pass_Word_2026!'
GEODE() { ./zig-out/bin/geode query --insecure --server "127.0.0.1:$PORT" -U geode -P "$PASS" "$@"; }

for batch in {0..19}; do
  base=$((batch * 50 + 1))
  q="CREATE"
  for i in $(seq 0 49); do
    id=$((base + i))
    val=$((id * 10))
    if [ $i -eq 0 ]; then
      q="$q (:GAP0257 {id: $id, value: $val})"
    else
      q="$q, (:GAP0257 {id: $id, value: $val})"
    fi
  done
  GEODE "$q" >/dev/null
done

# Confirm 1000 rows persisted.
GEODE "MATCH (n:GAP0257) RETURN count(n) AS c"
# → {"rows":[{"c":1000}],"status_class":"00000"}
```

### Trigger query (multi-column projection over 1000 nodes)

```bash
time GEODE "MATCH (n:GAP0257) RETURN n.id AS id, n.value AS value"
```

**Observed:**

```text
elapsed: 31s   (matches the client's --timeout default of 30s)
{"status_class":"00000",
 "ordered":false,
 "columns":[{"name":"id","type":"INTEGER"},{"name":"value","type":"INTEGER"}],
 "rows":[],                   ← EMPTY despite count(n)=1000
 ...}
```

### Bisection results

Holding the seed constant (1000 nodes, multi-column RETURN), varying only
the client's `--timeout` and the server's `GEODE_INLINE_RESULTS_MAX_ROWS`
env var (which controls page batch size for the protobuf-level pagination
the server emits over the stream):

| Client `--timeout` | Server `INLINE_RESULTS_MAX_ROWS` | Elapsed | Rows received | Result |
|---|---|---|---|---|
| 30 s (default) | 1000 (default) | 31 s | **0** | empty rows; status_class=00000 |
| 90 s | 1000 (default) | 91 s | **0** | empty rows after long wait |
| 5 s | 1000 (default) | 6 s | 0 | empty |
| 30 s | 200 | 31 s | partial | 11 of 20 messages received (~550 rows) |
| 30 s | 50 | 31 s | partial | 11 of 20 messages received (~550 rows) |
| 30 s | 10 | 32 s | partial | 37 of 100 messages received (~370 rows) |
| 30 s | 10000 (single huge msg) | 32 s | **0** | message lost entirely |

LIMIT clause bisection (server-side fast-path bypasses the streaming loop
when `LIMIT ≤ inline_results_max_rows`):

| Query | Elapsed | Result |
|---|---|---|
| `MATCH (n:GAP0257) RETURN n.id AS id, n.value AS value LIMIT 500` | 1.18 s | ✅ 500 rows returned |
| `MATCH (n:GAP0257) RETURN n.id AS id, n.value AS value LIMIT 550` | 1.31 s | ✅ 550 rows returned |
| `MATCH (n:GAP0257) RETURN n.id AS id, n.value AS value LIMIT 600` | 31.12 s | ❌ empty rows |
| `MATCH (n:GAP0257) RETURN n.id AS id, n.value AS value LIMIT 700` | 31.12 s | ❌ empty |
| `MATCH (n:GAP0257) RETURN n.id AS id, n.value AS value LIMIT 1000` | 31.09 s | ❌ empty |
| `MATCH (n:GAP0257) RETURN n.id AS id` (single col, no LIMIT, 1000 rows) | 1.29 s | ✅ 1000 rows |
| `MATCH (n:GAP0257) RETURN count(n) AS c` (1 row) | 1.17 s | ✅ |

The threshold is **between 550 and 600 rows when projecting 2 INTEGER
columns**, which corresponds to roughly 16–18 KiB of protobuf-encoded
response payload (each row ≈ 30 bytes encoded). Single-column RETURN is
~half the bytes per row and reaches 1000 rows (~10 KiB) without
triggering the bug.

The threshold is **byte-bound**, not row-bound or page-bound:

- 550 rows × 50/page = 11 pages × ~1.7 KiB = ~18.7 KiB total → stalls
- 370 rows × 10/page = 37 pages × ~360 bytes = ~13.3 KiB total → stalls
- 1000 rows × 1/big-page = 1 message × ~30 KiB → message lost entirely

i.e. the stream *cannot move* more than approximately 12–18 KiB of
application data once the application-level pagination batch boundary is
crossed, regardless of how that data is split across QUIC frames.

---

## What we have ruled out

1. **Server-side execution latency.** Server-side metrics show
   `mg_rwlock_shared_max_hold_ns_observed ≈ 66 ms` for the failing query
   — the executor finishes well within the budget. The wedge is in the
   write/read path AFTER the result rows are materialised.

2. **Server-side application pagination logic.** The geode page-emit loop
   (`src/server/quic_connection_handler.zig:3879-3896`) is straight
   forward and correctly sets `page.final = true` on the last page. Tested
   with `GEODE_INLINE_RESULTS_MAX_ROWS` ranging from 10 to 10000; the
   stall persists regardless. Forcing the PULL code path
   (`GEODE_INLINE_RESULTS=0`) also fails identically.

3. **Connection-level flow control.** `quic_min_flow_control_headroom`
   stays at ~256 MiB throughout the stall. The connection-level MAX_DATA
   window is not the limiter.

4. **Application-level encoding bug** (e.g. final-flag dropped in
   protobuf). Captured client output shows the *received* pages contain
   correct row payloads; the schema message also arrives intact. The
   issue is that **further messages after some count never arrive** —
   not that they arrive corrupted.

5. **Authentication / TLS.** All test queries use the same authenticated
   path; smaller queries succeed over the same connection.

6. **Client-side decode buffer cap.** `MAX_RECV_BUFFER_SIZE` in
   `geode-client-zig/geode_client_v2.zig` is 16 MiB — far above the
   observed stall point.

7. **Single-column vs multi-column query path divergence.** Both projections
   take the same execution code path and the same wire-format code path on
   the server; the only difference is the per-row payload size. The
   threshold tracks bytes, not column count.

8. **gRPC vs QUIC:** the gap_0257 spec explicitly fails over QUIC. (gRPC
   not exercised in this reproduction.)

---

## Suspected root cause

The pinned `quic_total_cwnd_bytes ≈ 12_411` value is exactly the standard
QUIC initial congestion window (≈ 10 packets × 1200 bytes per RFC 9002
§7.2). On loopback this should grow to many MiB within a handful of
RTTs (single-digit milliseconds). It does not — it remains stuck at the
initial value across the entire 30 s stall.

This is the strongest signal the team has so far: **the cwnd-growth path
is not progressing on the server, even though the client is actively
polling and (presumably) ACKing received packets.** Three concrete
hypotheses worth investigating in `~/src/devnw/zig/quic/src/quic/`:

### Hypothesis A: ACKs aren't being delivered to the cwnd-growth machinery

The server's `pollLoop` thread (separate from the connection-handler
thread that calls `stream.writeAll`) is supposed to drive ingress
processing including ACK frame consumption. If poll-thread ACK processing
is racing with the worker thread — or worse, never running because of a
poll/lock contention pattern — cwnd would stay at its initial value.

This is *adjacent to but distinct from* `BUG_ACK_DATA_RACE.md` in this
same `docs/` directory: that bug describes ACK *generation* corruption,
whereas this bug looks like ACK *consumption* not advancing
`bytes_in_flight` / cwnd state.

Concrete inspection points:

- `src/quic/connection/methods_c.zig` — `processFrames` ACK handling.
- `src/quic/connection/cc.zig` (or wherever cwnd update on ACK lives) —
  is `onAckReceived(...)` definitely being called for every received
  ACK frame on the connection?
- The `poll_sync` cooperation between the dedicated `pollLoop` thread
  in `geode/src/transport/quic.zig:410` and worker threads doing
  `stream.writeAll`.

### Hypothesis B: send-side flow control window not being extended

Server sends 12 KiB worth of data. Stream-level `peer_max_stream_data`
governs how much more it can put on the wire before the receiver must
issue a `MAX_STREAM_DATA` extension.

`local_max_stream_data` defaults to 16 MiB
(`src/quic/connection/conn.zig:779-780`), so a fresh stream should have
plenty of headroom. **But:** if the client never *sends* a
`MAX_STREAM_DATA` frame (or sends one whose value does not actually
extend the peer's send budget), the server hits the peer window and
silently stops sending. Combined with cwnd not growing, this is
indistinguishable from the symptom.

Concrete inspection points:

- `src/quic/connection/flow_control.zig:53 shouldExpandStreamWindow`
  and `:86 shouldSendMaxStreamData` — when does the receiver decide
  to advertise window expansion?
- `src/quic/connection/methods_b.zig:558-564` — receive-side
  bookkeeping after a stream read consumes bytes.
- `src/quic/connection/stream.zig:63-64,207` — `local_max_stream_data`
  vs `peer_max_stream_data` lifecycle.

### Hypothesis C: poll-thread vs handler-thread deadlock under loopback timing

On loopback the round-trip is so fast that ACKs may arrive *while* the
handler thread is still inside `stream.writeAll`, before the
`pollLoop` thread has yielded. If the two threads contend on the
connection's internal mutex in just the right pattern, ACK consumption
could be deferred until the next outer poll cycle, which itself is
gated on the handler thread completing — yielding a scheduler-induced
livelock that looks like a timeout.

Concrete inspection points:

- `geode/src/transport/quic.zig:732-756` — the spin-with-500μs-sleep
  pattern in `QuicStream.writeAll` on `FlowControlBlocked` / `n == 0`.
  Each iteration does NOT call into `transport.poll`, relying on the
  separate poll thread to drive the QUIC state machine.
- `geode/src/transport/quic.zig:388-401 QuicTransport.poll` — the
  `poll_sync` cooperation primitive.
- The `connection.writeStream` impl path in this library — does it
  acquire the connection mutex held by the polling thread? If the poll
  thread holds the mutex while delivering an ACK to cc.zig, the
  worker's writeAll-spin can race in a way that delays observation of
  the cwnd extension.

---

## Why this is hard to fix incrementally

The classic "spray application-level fixes at it" approaches all fail:

- Reducing the proto-level page size below the threshold — the client
  receives more, smaller messages but **still hits the wall** at roughly
  the same total byte count. The problem is below the application
  framing layer.
- Increasing `--timeout` — the client just polls longer, still receives
  no further messages, eventually times out with the partial result.
- Switching server inline-vs-PULL paths — both fail identically.
- Bumping the QUIC `max_stream_data` defaults — they're already 16 MiB,
  far above the observed stall point.

The fix has to land **inside the QUIC library** at the cwnd / stream
window / poll-cooperation layer.

---

## Reproducer outside Geode

The minimum reproducer is "send N length-prefixed protobuf messages
totalling > ~16 KiB on a single bidirectional stream from server to
client, on loopback, where the client reads them via
`quic.readStream`-in-loop." A pure-`zig/quic` test against this pattern
would isolate the bug from anything Geode-specific. Recommended
benchmark target:

```text
N messages × M bytes each, where N×M > 20 KiB,
loopback, single connection, single bidi stream.
Client reads in-loop until it sees a sentinel "final" message
(application-level) or a stream FIN.
Bug fires when client never receives the sentinel even though
server's writeAll calls all returned success.
```

If a quic library test exhibits this, the fix can be developed entirely
within `zig/quic` without dragging Geode into the loop. (Geode's role
in surfacing the bug is purely incidental — it happens to be the highest-
volume real-world consumer.)

---

## Workarounds in geode-test-harness (until fixed)

Until a real library-level fix lands, the geode test harness treats
both `gap_0257_orderby_large_resultset.yml` and
`transaction_chunked_execution.yml` as **known pre-existing failures**.
This is recorded in the `geode/.../memory/preexisting_harness_failures.md`
note and in the harness's `make test-everything-otel` baseline (12
failed = 11 pre-existing + 0 actionable in steady state).

Application-side workarounds clients can use *today*:

- Add `LIMIT n` (with `n ≤ ~ payload_threshold / bytes_per_row`) to all
  large MATCH queries.
- Project a single column rather than multiple, to halve bytes/row.
- Use streaming PULL with smaller pages — partial results still arrive,
  so you can pick up where you left off — *but* the stream is still
  stuck after that point, so this is only useful for "first N rows"
  flows, not full-result reads.

Operationally the bug means **Geode cannot reliably return result sets
above ~16 KiB** over a single QUIC stream until this is fixed.

---

## Investigation log (this session)

| Step | What we tried | Result |
|---|---|---|
| 1 | Reproduce against running harness's geode | confirmed; 7 GAP-0257 timeouts + 4 chunked-tx timeouts |
| 2 | Stand up isolated geode on free port | reproduces identically |
| 3 | Vary `--timeout {5,30,90}` | elapsed scales with timeout; same empty-rows outcome |
| 4 | Vary `GEODE_INLINE_RESULTS_MAX_ROWS {10,50,200,1000,10000}` | partial results scale roughly with page count, but always stall |
| 5 | Vary `LIMIT {500..1001}` to find row-count threshold | 550 works, 600 fails |
| 6 | Compare single vs multi-column projection | single-col 1000 rows works; multi-col fails — points at bytes, not row count |
| 7 | Force `GEODE_INLINE_RESULTS=0` (PULL path) | fails identically |
| 8 | Inspect server-side metrics | `cwnd_bytes ≈ 12411` pinned; `flow_control_headroom ≈ 256 MiB` (conn-level fine) |
| 9 | Check `MAX_RECV_BUFFER_SIZE` in geode-client-zig | 16 MiB — not the cap |
| 10 | Audit server-side page emit loop | logic correct, `page.final = true` set on last page |
| 11 | Audit `QuicStream.writeAll` retry loop | spin-with-500µs-sleep; 10 s ceiling never tripped |
| 12 | OTel collector spans | only metrics arrived; trace pipeline silent (separate file-perms issue on the harness collector mount; not blocking) |

Stopped here because the next productive step is to instrument the
QUIC library directly (likely `cc.zig` cwnd-extension and
`flow_control.zig` window-extension) which is library-internal work
better done in a focused session against the QUIC repo, not Geode's.

---

## See also

- `BUG_ACK_DATA_RACE.md` — adjacent ACK-generation corruption issue,
  fixed by adding `conn.mu` around incoming-packet processing. The
  current bug is *not* the same defect but lives in the same general
  area (poll-thread vs worker-thread cooperation around connection
  state).
- `ARCHITECTURE.md` — overall threading model.
- `PERF_GAP_ANALYSIS.md` — historical perf gap log.
- Geode side: `~/src/devnw/codepros/geode/geode/.claude/projects/-data-home-benji-src-devnw-codepros-geode-geode/memory/preexisting_harness_failures.md`
  (memory note tracking which Geode integration specs are gated on this bug).
