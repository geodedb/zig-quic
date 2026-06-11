# Defensive AppSec Review — zig-quic (QUIC RFC 9000 + HTTP/3)

**Target:** `/home/benji/src/gl/gitlab.com/devnw/zig/quic` · branch `main` · HEAD `99a6025` (clean worktree)
**Framework:** OWASP Top 10:2025 + CIS Controls v8.1.2 · evidence-first defensive review
**Date:** 2026-06-11 · **Reviewer:** appsec-reviewer

---

## 1. Scope and Assumptions

**Reviewed (read directly from the working tree):**

- QUIC parsing/protocol: `src/quic/varint.zig`, `src/quic/frame/*.zig`, `src/quic/packet.zig`, `src/quic/transport_params.zig`.
- Crypto: `src/quic/crypto_quic.zig`, `src/quic/crypto_zig.zig`, `src/quic/connection/key_update.zig`, `reset_token.zig`, `crypto_utils.zig`, `crypto_buffer.zig`, `anti_replay.zig`, `pem.zig`.
- Address validation / amplification / Retry / path / migration: `src/quic/token.zig`, `connection/amplification.zig`, `endpoint/incoming.zig`, `endpoint/incoming/module_a.zig`/`module_c.zig`, `endpoint.zig`, `connection/methods_a.zig`, `connection/methods_c.zig`, `endpoint/frame_handler.zig`.
- Resource limits / flow control: `connection/flow_control.zig`, `crypto_buffer.zig`, `stream.zig`, `limits.zig`, `idle.zig`, `endpoint/lookup.zig`, `endpoint/incoming/module_b2.zig`, `stream_scheduler.zig`.
- HTTP/3: `src/h3/server.zig`, `src/h3/client.zig`, `src/h3/varint.zig`.
- Binaries + scripts: `cmd/*.zig`, `create_test_certs.sh`, `scripts/*.sh`, `interop/*.sh`.

**Deduplication:** I read `docs/SECURITY_GAP_ANALYSIS.md`, `docs/SECURITY_REVIEW_NOTES.md`, `docs/GAP_ANALYSIS.md`, `docs/GAP_ANALYSIS_RESOLVED.md`, and `docs/CRYPTO_AUDIT.md` first. All 14 prior security findings and the resolved gap items are tracked as Closed. I verified the prior fixes are **present and not regressed** (allocation caps, ACK range ceiling, CID>20 → error, timing-safe Retry/reset/token comparisons, removed amplification env var, `enable_retry=true` default, `secureZero` on key teardown, anti-replay wiring, mTLS wiring, no `catch unreachable` in active crypto). **This report contains only NEW findings** not in those documents.

**Assumptions:**

- All UDP datagrams are attacker-controlled (no threat-model doc; RFC 9000/9001/9002 security-considerations sections are the de-facto requirements).
- Production deployment is the **library** consumed by other Zig projects (e.g. geode transport) as a public-facing QUIC server/client. `cmd/` and `qns-endpoint` are test/interop tooling (scored lower).
- `std.Random.DefaultPrng` = Xoshiro256++ (non-cryptographic), `std.os.linux.getrandom` returns a raw syscall result (negative errno / short count on failure). Both are stable, documented Zig/Linux facts; the code itself confirms the DefaultPrng-is-non-crypto understanding at `cmd/quic-client-comprehensive.zig:253-257`.

**Not covered:** transitive dependency internals (tls v0.1.10, thread_pool, otel — out of scope per contract); full dynamic exploitation (static review only); the 529 skipped tests (tracked under GAP-0004/GAP-0013); congestion-control correctness beyond resource-exhaustion relevance.

---

## 2. Executive Summary

- **One Critical: receive-side flow control is not enforced.** A peer can drive unbounded heap allocation by sending STREAM data beyond the advertised `MAX_STREAM_DATA`/`MAX_DATA` windows, or by sending out-of-order (gapped) segments that are buffered forever. No `FLOW_CONTROL_ERROR` is ever raised on receive (`methods_a.zig:pushStreamFrame` → `stream.zig:insert`). This is the highest-impact issue and is reachable post-handshake from any peer.
- **Two High: pre-authentication connection migration + unauthenticated amplification credit.** The short-header path commits a peer-address change (resets anti-amplification state, emits PATH_CHALLENGE to the new address) based purely on a cleartext DCID match, **before** the packet's AEAD tag is verified (`endpoint.zig:1336-1350` → `onPathAddressChanged`), and credits the unauthenticated datagram to the anti-amplification RX budget (`module_c.zig:201`). Together these allow off-path traffic redirection and reflection toward a spoofed victim.
- **One High: weak/unchecked randomness for security-critical values.** NEW_CONNECTION_ID connection IDs (and the stateless-reset tokens derived from them) are generated from a 64-bit-seeded **non-cryptographic** Xoshiro PRNG (`methods_c.zig:545-552, 706`), and every `getrandom()` call in the codebase discards its return value, silently falling back to uninitialized/stale stack memory on syscall failure (11 sites incl. reset-token base, path-challenge data, retry SCID, server SCID, generated secrets).
- **Several Medium:** unbounded `stream_txs` map growth from peer `MAX_STREAM_DATA` for arbitrary stream IDs (`frame_handler.zig:296`); replayable/type-confusable Retry/NEW_TOKEN tokens (no nonce/single-use, no type discriminator); unbounded received-DATAGRAM queue; missing 2^60 bound + monotonic check on peer `MAX_STREAMS`; 0-RTT encoder that can emit an unprotected header and swallows HP errors.
- **Overall confidence: High** for the parsing-path negatives (prior fixes intact, slice-based production parser is bounds-clean) and for the flow-control, migration, and randomness findings (traced to source). The crypto primitives themselves (AEAD nonce construction, HP sampling bounds, Retry tag, HKDF labels) are **correctly implemented** — the gaps are in *how* state transitions and randomness feed those primitives.

---

## 3. Findings Table

| ID | Severity | Confidence | Title | Location | OWASP 2025 | Status |
|----|----------|-----------|-------|----------|-----------|--------|
| QC-01 | Critical | High | Receive-side flow control not enforced → unbounded buffering DoS | `connection/methods_a.zig:849-851,891`; `connection/stream.zig:153-162,183-186` | A06 Insecure Design / A10 | New |
| QC-02 | High | High | Connection migration committed before AEAD authentication (off-path redirect + reflection) | `endpoint.zig:1336-1350,2549-2573` | A07 Auth Failures | New |
| QC-03 | High | High | Anti-amplification RX budget credited with unauthenticated bytes (short-header path) | `endpoint/incoming/module_c.zig:201` | A06 Insecure Design | New |
| QC-04 | High | High | Connection IDs / reset tokens from non-CSPRNG; all `getrandom()` returns discarded | `connection/methods_c.zig:545-552,689,706`; +10 sites | A04 Cryptographic Failures | New |
| QC-05 | Medium | High | Unbounded `stream_txs` map growth from peer MAX_STREAM_DATA on arbitrary stream IDs | `endpoint/frame_handler.zig:292-298` | A06 Insecure Design | New |
| QC-06 | Medium | High | Retry/NEW_TOKEN tokens replayable; no type discriminator | `token.zig:32-81,120-169`; `endpoint/incoming.zig:457-517,686` | A07 Auth Failures | New |
| QC-07 | Medium | High | Unbounded received-DATAGRAM queue | `connection/methods_a.zig:901-905`; `conn.zig:826` | A06 Insecure Design | New |
| QC-08 | Medium | High | Peer MAX_STREAMS accepted without 2^60 bound / monotonic check | `endpoint/frame_handler.zig:328-347` | A10 Mishandling Exceptions | New |
| QC-09 | Medium | High | 0-RTT encoder emits unprotected header on short ciphertext; swallows HP errors | `packet.zig:1147-1162` | A04 Cryptographic Failures | New |
| QC-10 | Medium | Medium | PATH_RESPONSE accepted from any address; non-constant-time compare | `connection/methods_a.zig:1055-1066`; `endpoint/frame_handler.zig:439-444` | A07 Auth Failures | New |
| QC-11 | Medium | Medium | RX-triggered key update has no rate limit / prior-update-confirmed gate | `endpoint/incoming/module_b.zig:971-1019`; `connection/methods_b.zig:1734-1760` | A04 Cryptographic Failures | New |
| QC-12 | Low | High | Server-side path traversal in qns interop endpoint file server | `cmd/qns-endpoint.zig:933-946` | A01 Broken Access Control | New |
| QC-13 | Low | High | Anti-replay cache keyed on 64-bit Wyhash (fixed seed) → targeted false-reject | `anti_replay.zig:138-146` | A04 Cryptographic Failures | New |
| QC-14 | Low | High | TLS keylog file created world-readable (0o644) | `connection/methods_a.zig:20` | A04 Cryptographic Failures | New |
| QC-15 | Low | High | Interop/test cert scripts install private keys world-readable | `scripts/interop_assets.sh:85-110`; `interop_local_bootstrap.sh:153-174`; `interop_full.sh:123-148`; `create_test_certs.sh:11,19,31,57` | A02 Security Misconfiguration | New |
| QC-16 | Low | Medium | `stateless_reset_base` derived from per-connection secret, not endpoint-static key | `connection/methods_c.zig:675-691` | A04 Cryptographic Failures | New |
| QC-17 | Low | Medium | Nix dev-bootstrap installer executed without hash/signature verification | `scripts/install_pkgs.sh:128-179` | A08 Software/Data Integrity | New |

---

## 4. Finding Details

### QC-01 — Receive-side flow control is not enforced (Critical)

**Evidence.** `src/quic/connection/methods_a.zig:804-897` (`pushStreamFrame`) is the production sink for received STREAM data. After a stream-*count* check (`validatePeerStreamLimit`, line 832), data is inserted with no window check:

```zig
// methods_a.zig:849-851
if (data.len > 0) {
    s.insert(self.allocator, offset, data);   // copies into a fresh allocation, no FC check
    s.tryDrain(self.allocator);
...
// methods_a.zig:891
self.conn_recv_total +%= data.len;            // wrapping add, never compared to local_max_data
```

`StreamRx.insert` (`stream.zig:153-162`) unconditionally `alloc.alloc(u8, data.len)` + appends to `bufs`, with **no cap** on `bufs.len`, on per-stream buffered bytes, or on per-connection bytes. `tryDrain` (`stream.zig:165-190`) only drains segments contiguous at `recv_off`; any segment with `seg.off > recv_off` is retained in `bufs` indefinitely (lines 183-186). `flow_control.zig` provides **only send-side** helpers (`canSendStreamData`, `streamFlowWindow`, `canOpenStream`) and window-growth helpers — there is no `canReceive`/enforcement function, and none is called from the receive path. `local_max_stream_data` (default 16 MiB) and `local_max_data` (default 256 MiB) are used solely to *advertise* windows.

**Attack scenario (non-destructive).** A peer that has completed the handshake (or sends 0-RTT) opens a stream and sends STREAM frames whose `offset + len` far exceeds the 16 MiB advertised stream window, or sends many frames at increasing non-contiguous offsets (e.g. `offset = k * 2_000_000` with a 1-byte gap). Every frame is copied into `bufs` and never drained. Connection-level `conn_recv_total` is tracked with a wrapping `+%=` and never enforced against `local_max_data`. Memory grows until OOM.

**Impact.** Remote unauthenticated-after-handshake memory-exhaustion DoS of the server process; one misbehaving/malicious peer can exhaust host memory. Violates RFC 9000 §4.1–§4.2 (receiver MUST treat data beyond the advertised limit as `FLOW_CONTROL_ERROR` 0x03 and MUST bound out-of-order buffering).

**Root cause.** Flow control was implemented for the send path and window advertisement only; the receive path has no enforcement and no buffering ceiling.

**Remediation.** In `pushStreamFrame`, before `s.insert`: reject `offset + data.len > s.local_max_stream_data` and `conn_recv_total_after > local_max_data` with `error.FlowControlError` (→ CONNECTION_CLOSE 0x03). Cap total out-of-order buffered bytes per stream and per connection (e.g. ≤ the receive window), dropping/closing when exceeded. Replace the `+%=` accumulator with a checked add. Add a `canReceive(offset, len)` helper in `flow_control.zig` mirroring the send-side ones.

**Regression tests.** (1) Send STREAM beyond `local_max_stream_data` → expect CONNECTION_CLOSE FLOW_CONTROL_ERROR, bounded RSS. (2) Send N gapped segments → assert `bufs` bytes ≤ window. (3) Connection-level: sum across streams > `local_max_data` → FLOW_CONTROL_ERROR.

**Mappings.** CWE-770, CWE-400, CWE-191 (FC accumulator wrap). OWASP A06/A10. RFC 9000 §4.1–§4.2.

---

### QC-02 — Connection migration committed before AEAD authentication (High)

**Evidence.** In the short-header receive path, routing is decided by a cleartext DCID match, and a peer-address change is committed immediately:

```zig
// endpoint.zig:1336-1350
lookup_result = lookup.findConnectionByDcid(&self.conns, norm_peer, bytes, null);
if (lookup_result.conn) |c| {
    if (lookup_result.nat_rebinding or !conn_mod.SockAddr.eq(&c.peer, &norm_peer)) {
        if (!self.onPathAddressChanged(c, norm_peer, peer_h, lookup_result.dcid_len)) { ... return ...; }
    }
}
// decryption happens LATER in incoming.processShortHeaderResolved → module_c.zig:271
```

`onPathAddressChanged` (`endpoint.zig:2549-2573`) calls `c.setPeer(new_peer)`, zeroes `bytes_rx_unvalidated`/`bytes_tx_unvalidated`, clears `address_validated`, inserts a new routing key, and calls `c.sendPathChallenge()` — all before any tag check. The later decrypt-failure path (`module_c.zig:276-297`) simply `return`s; it does **not** revert `setPeer`/the migration. Short-header DCIDs are cleartext in every 1-RTT packet.

**Attack scenario.** An off-path attacker observes (or replays a captured 1-RTT packet bearing) a valid DCID and sends it with a spoofed source address. The server overwrites the legitimate client address with the attacker-chosen address, resets the anti-amplification budget, and emits a PATH_CHALLENGE (plus any pending 1-RTT data) to that address. RFC 9000 §9.3 requires the address change to be driven by a packet that is *newly received and successfully authenticated*, and to keep using the old validated path until the new path is validated.

**Impact.** Traffic redirection / DoS of the legitimate client (its packets now route to a stale key); use of the server as a reflector toward a spoofed victim (PATH_CHALLENGE + in-flight data); resets amplification accounting (amplifies QC-03).

**Root cause.** Migration state transition is performed at the routing/lookup layer (pre-decrypt) rather than after AEAD verification.

**Remediation.** Defer `setPeer`/state-reset/PATH_CHALLENGE until a packet from the new address **authenticates**. On a path change, probe with PATH_CHALLENGE while continuing to send non-probing traffic on the old validated path; only commit the new peer after PATH_RESPONSE returns on the new path. Ensure decrypt failure leaves the original peer untouched. Gate the `nat_rebinding` fallback (`lookup.zig`) likewise.

**Regression tests.** Spoofed-source short-header packet with a valid DCID but wrong keys → assert peer address unchanged, no PATH_CHALLENGE emitted, amplification counters unchanged. Authenticated migration → assert challenge sent to new path only after auth, old path still used until validated.

**Mappings.** CWE-290, CWE-940, CWE-406. OWASP A07. RFC 9000 §9.3.

---

### QC-03 — Anti-amplification RX budget credited with unauthenticated bytes (High)

**Evidence.** `src/quic/endpoint/incoming/module_c.zig:201`:

```zig
// Track bytes received from unvalidated address for anti-amplification (RFC 9000 §8.1)
conn.addRxUnvalidated(bytes.len);          // line 201 — BEFORE decryptShortHeaderWithKeyRotation() at line 271
```

The full datagram length is credited to the anti-amplification RX counter before the AEAD tag is verified. Contrast the Initial path (`incoming.zig:823-824`), which correctly credits only *after* `decryptInitialPacket` succeeds. Chained with QC-02 (which zeroes `bytes_rx_unvalidated` on migration), this grants the server a `3 × (attacker-chosen size)` TX allowance toward the (possibly spoofed) new address.

**Attack scenario.** After triggering a migration (QC-02), the attacker sends large unauthenticated datagrams from the spoofed source; each inflates the RX budget, letting the server send 3× that volume to the victim. RFC 9000 §8.1 requires counting only bytes in *successfully processed* packets.

**Impact.** Defeats the anti-amplification limit on the short-header path; turns the server into an amplifying reflector when combined with QC-02.

**Remediation.** Move `addRxUnvalidated(bytes.len)` to after successful decryption (mirror the Initial path at `incoming.zig:823-824`).

**Regression test.** Send undecryptable short-header bytes from an unvalidated address → assert `bytes_rx_unvalidated` unchanged.

**Mappings.** CWE-406, CWE-345. OWASP A06. RFC 9000 §8.1.

---

### QC-04 — Connection IDs / reset tokens from non-CSPRNG; `getrandom()` returns discarded (High)

**Evidence — non-CSPRNG CIDs.** `src/quic/connection/methods_c.zig:545-552`:

```zig
fn cidLifecyclePrng(self: *Connection) std.Random.DefaultPrng {
    var seed_bytes: [8]u8 = undefined;
    _ = std.os.linux.getrandom(&seed_bytes, seed_bytes.len, 0);   // return ignored
    var seed = std.mem.readInt(u64, &seed_bytes, .little);
    seed ^= self.next_cid_sequence;
    seed ^= self.issued_cids << 32;
    if (seed == 0) seed = 0xdecafbad_c1d5eed;
    return std.Random.DefaultPrng.init(seed);                     // Xoshiro256++ — NOT a CSPRNG
}
```

`acquireLocalCid` (line 706) fills CID bytes from this PRNG (`rand.random().bytes(&cid_bytes)`) and derives the **stateless-reset token from those CID bytes** (line 711 → `reset_token.zig:4-15`, CID is the HKDF IKM). NEW_CONNECTION_ID frames advertise these CIDs (line 622-627).

**Evidence — discarded `getrandom` everywhere.** All 11 sites discard the return: `methods_c.zig:547,689`; `methods_a.zig:981` (path challenge); `endpoint/incoming.zig:466` (retry SCID); `endpoint/server.zig:219,346` (seed, initial SCID); `endpoint.zig:205,647,704` (seeds, generated secrets); `algorithms/sharding.zig:21`; `endpoint/client.zig:55`. On EINTR / early-boot entropy unavailability / short read, the destination keeps `undefined` stack contents (often zero/stale).

**Attack scenario.** (a) Xoshiro256++ state is recoverable from a handful of outputs; an observer who collects several advertised CIDs can predict future CIDs — defeating CID unlinkability (RFC 9000 §5.1) and letting an attacker pre-position packets/migration probes against not-yet-issued CIDs (feeds QC-02). The seed is only 64 bits and partially derived from observable counters. (b) On a `getrandom` failure, `stateless_reset_base` (methods_c.zig:689), `path_challenge_data`, retry SCID, or a generated secret can be zero/stale, making reset tokens and path-challenge data predictable.

**Impact.** Predictable CIDs (privacy + migration-spoofing assist); on entropy failure, predictable reset tokens / path challenges / secrets.

**Remediation.** Generate CID bytes directly from the OS CSPRNG with a checked return — use the existing `compat.randomBytes` (`compat.zig:162-166`, the documented `std.crypto.random.bytes` replacement) or `std.posix.getrandom` (which loops on EINTR and errors otherwise) — not a seeded `DefaultPrng`. Wrap every random draw in a helper that asserts the full requested length was returned and fails closed otherwise.

**Regression tests.** Statistical/sequence test that two consecutive connections' CIDs are not Xoshiro-predictable from prior outputs; fault-injection test that a failing `getrandom` returns an error rather than emitting a zero buffer.

**Mappings.** CWE-338, CWE-330, CWE-252. OWASP A04. RFC 9000 §5.1, §10.3.

---

### QC-05 — Unbounded `stream_txs` map growth from peer MAX_STREAM_DATA (Medium)

**Evidence.** `src/quic/endpoint/frame_handler.zig:292-298` (`handleMaxStreamData`): for any `stream_id` not already present, it inserts a new `StreamTx` entry:

```zig
} else {
    // Stream not yet created on our side - store for when it is created
    ctx.conn.stream_txs.put(m.stream_id, .{ .peer_max_stream_data = m.max }) catch { ... };
}
```

The 62-bit `stream_id` is peer-chosen; there is no validity check (e.g. that it is a locally-initiable stream) and no bound on the number of distinct entries. MAX_STREAM_DATA frames are a few bytes each. This bypasses the receive-side `validatePeerStreamLimit` (which guards `streams_rx`, not `stream_txs`).

**Attack scenario.** Peer streams MAX_STREAM_DATA with monotonically increasing stream IDs; `stream_txs` (an `AutoHashMap`) grows unbounded → memory exhaustion. RFC 9000 §19.10: MAX_STREAM_DATA for an invalid/send-unidirectional stream is a `STREAM_STATE_ERROR`.

**Impact.** Memory-exhaustion DoS, cheaper than QC-01 (tiny frames).

**Remediation.** Validate the stream ID (correct type/initiator, within plausible bounds); only update existing legitimate streams or reject with `STREAM_STATE_ERROR`. Cap pre-creation TX state entries.

**Regression test.** Flood MAX_STREAM_DATA with distinct IDs → assert bounded `stream_txs.count()` or CONNECTION_CLOSE.

**Mappings.** CWE-770, CWE-400. OWASP A06. RFC 9000 §19.10.

---

### QC-06 — Retry/NEW_TOKEN tokens are replayable and type-confusable (Medium)

**Evidence.** Tokens are `timestamp(8) ‖ ip_len(1) ‖ ip ‖ dcid_len(1) ‖ dcid ‖ hmac(32)` (`token.zig:50-51`), produced by one `encode` (`token.zig:32-81`) and validated by one `authenticatedDcid` (`token.zig:120-169`) that checks expiry + source IP + HMAC. There is **no nonce, no single-use cache, and no Retry-vs-NEW_TOKEN type byte**. A valid token grants `address_validated = true` (`incoming.zig:686`), and `verifyAndExtractDcid` (`incoming.zig:457-517`) treats the embedded CID as a Retry ODCID, binding it into `original_dcid_override`/`retry_validated`.

**Attack scenario.** (1) **Replay:** the token travels in cleartext (Retry packet + the client's follow-up Initial). Any party that captures it can replay it from the same source IP for the full validity window (default 60 s) to skip Retry and force server connection allocation. (2) **Type confusion:** a stale NEW_TOKEN-issued token is accepted on the Retry-validation path and its embedded CID is mis-bound as a Retry ODCID, corrupting the `original_destination_connection_id` transport-parameter binding for a non-Retry flow. RFC 9000 §8.1.4 requires distinguishing the two token types and protecting against replay.

**Impact.** Address-validation replay (defeats part of Retry's anti-spoofing value); transport-parameter binding corruption via type confusion.

**Remediation.** Add a token-type discriminator byte (RETRY vs NEW_TOKEN). For Retry tokens use a short validity plus a single-use nonce/strike cache. Only treat a token's CID as a Retry ODCID when the type byte is RETRY.

**Regression tests.** Replay a captured Retry token from the same IP → expect rejection after first use. Present a NEW_TOKEN-type token on the Retry path → expect it is not used as an ODCID source.

**Mappings.** CWE-294, CWE-384. OWASP A07. RFC 9000 §8.1.4. (Positive: the token HMAC, IP, and expiry comparisons are constant-time/correct — `token.zig:136,144-147,167`.)

---

### QC-07 — Unbounded received-DATAGRAM queue (Medium)

**Evidence.** `src/quic/connection/methods_a.zig:901-905` (`pushDatagram`) copies each received DATAGRAM payload and appends to `dgram_inbox` (`conn.zig:826`) with no length cap. `frame_handler.zig` swallows the push error, so growth continues to OOM.

**Attack scenario.** With the DATAGRAM transport parameter enabled, a peer floods DATAGRAM frames; if the application drains slower than arrival (or not at all), `dgram_inbox` grows without bound. RFC 9221 datagrams are not flow-controlled, so the receiver must impose its own queue bound.

**Impact.** Memory-exhaustion DoS where DATAGRAM is enabled.

**Remediation.** Bound `dgram_inbox` length/bytes; drop oldest or refuse when full.

**Mappings.** CWE-770, CWE-400. OWASP A06. RFC 9221.

---

### QC-08 — Peer MAX_STREAMS accepted without 2^60 bound / monotonic check (Medium)

**Evidence.** `src/quic/endpoint/frame_handler.zig:328-347` stores `peer_max_streams_bidi`/`_uni = msb.max` verbatim — no `≤ 2^60` check (RFC 9000 §4.6/§19.11 requires `> 2^60` → `FRAME_ENCODING_ERROR`) and no monotonic guard (the value may decrease).

**Impact.** Spec-conformance/robustness gap; a 2^62-1 value combined with an application that opens streams to the advertised limit could drive large local allocation. Lower severity than QC-01/QC-05 because it governs *our* send side.

**Remediation.** Reject `max > (1 << 60)` with FRAME_ENCODING_ERROR; ignore decreases.

**Mappings.** CWE-20, CWE-770. OWASP A10. RFC 9000 §4.6.

---

### QC-09 — 0-RTT encoder emits unprotected header on short ciphertext; swallows HP errors (Medium)

**Evidence.** `src/quic/packet.zig:1147-1162` (`encode0RTTProtected`):

```zig
const sample_offset = pn_offset + 4;
if (sample_offset + 16 <= buf.items.len) {
    ... crypto.headerProtect(...) catch |err| {
        logger.err("header protection failed: {s}", .{@errorName(err)});  // swallowed
    };
}
// else: header protection NOT applied; packet still returned
```

If the ciphertext is too short for a 16-byte sample, the packet is returned with the first byte and packet-number bytes in cleartext; if `headerProtect` errors, it is only logged and the unprotected packet is still emitted. The AES path in `protectPacket` (`crypto_quic.zig:285-289`) and the short-header path (`packet.zig:223-230`, which *pads* to guarantee a sample) both fail-closed instead.

**Impact.** Emits a 1-RTT/0-RTT-class packet with an unprotected header, leaking true PN length/low bits and reserved bits, breaking the AEAD/HP coupling (RFC 9001 §5.4). Limited to the 0-RTT send path.

**Remediation.** Pad the payload to the minimum sample length (as `encodeShortProtectedInto` does) and propagate `headerProtect` errors (return `error.AuthenticationFailed`) instead of logging-and-continuing.

**Mappings.** CWE-325, CWE-755. OWASP A04. RFC 9001 §5.4.

---

### QC-10 — PATH_RESPONSE accepted from any address; non-constant-time compare (Medium)

**Evidence.** `src/quic/connection/methods_a.zig:1055-1066` (`onPathResponse`) compares the 8 challenge bytes with `std.mem.eql` (not `std.crypto.timing_safe.eql`) and sets `address_validated = true` regardless of which source address the response arrived from. The dispatcher (`frame_handler.zig:439-444`) does not pass/compare `ctx.peer`. The companion `seedPathChallengeData` (`methods_a.zig:980-985`) ignores the `getrandom` return and, on the zero-fallback, derives challenge data from `pn_app_tx ^ path_validation_attempts` — both guessable.

**Attack scenario.** Chained with QC-02/QC-04: an attacker who triggers migration and observes the server's PATH_CHALLENGE echoes its 8 bytes from the spoofed address and flips `address_validated = true`, completing path validation off-path. The predictable fallback challenge makes forging a valid response possible even without observing the challenge in the entropy-failure case.

**Remediation.** Bind PATH_RESPONSE acceptance to the address under validation; use `std.crypto.timing_safe.eql`; check the `getrandom` return and fail the probe rather than using a predictable fallback.

**Mappings.** CWE-940, CWE-208, CWE-330. OWASP A07. RFC 9000 §8.2.

---

### QC-11 — RX-triggered key update has no rate limit / prior-update-confirmed gate (Medium)

**Evidence.** When a packet decrypts under the derived NEXT keys, `promoteToNextKeys` (`endpoint/incoming/module_b.zig:971-1019`) toggles `rx_key_phase` and `syncTxKeysAfterRxUpdate` (`connection/methods_b.zig:1734-1760`) immediately rotates TX keys, guarded only by `if (self.tx_key_phase == self.rx_key_phase) return;`. There is no requirement that the local side's prior update was confirmed and no rate limit. (RX key *retention* is correctly bounded via `rx_prev_allow = 16`.)

**Attack scenario.** A peer that flips its key phase on every packet forces `deriveNextTrafficSecret` + key-schedule derivation per received packet (CPU), contrary to RFC 9001 §6.1/§6.5 (MUST NOT initiate a new update until the prior one is confirmed; ~one update per RTT).

**Remediation.** Gate forced TX rotation on confirmation of the local prior update (don't rotate while `tx_update_in_progress`); rate-limit forced updates to ~one per RTT.

**Mappings.** CWE-400. OWASP A04. RFC 9001 §6.1, §6.5, §6.6.

---

### QC-12 — Server-side path traversal in qns interop endpoint (Low)

**Evidence.** `cmd/qns-endpoint.zig:933-946`: the wire request path is concatenated into `/www{path}` with no `..`/normalization and read via `readFileAlloc` (which follows the path through `std.Io.Dir.cwd().openFile`). `GET /../../etc/passwd` → `/www/../../etc/passwd` → `/etc/passwd`.

**Mitigation / scoping.** This is the QUIC-interop-runner test endpoint, gated on `ROLE`/`TESTCASE`, and in the shipped Docker path runs **unprivileged** (dropped to the `quic` user by `interop/run_endpoint.sh`), constraining reads to that user. Hence Low. Still a network-reachable arbitrary-file-read with no containment. The client download paths (`qns-endpoint.zig:1217,1341,1461`) strip only a leading `/` and likewise don't reject `..`, but derive from the client's own `REQUESTS` env (self-inflicted).

**Remediation.** Reject paths containing `..` or NUL, require a leading `/`, and verify the canonical resolved path stays under `/www` before reading.

**Mappings.** CWE-22. OWASP A01.

---

### QC-13 — Anti-replay cache keyed on 64-bit Wyhash, fixed seed (Low)

**Evidence.** `src/quic/anti_replay.zig:138-146`: `hashBytes` = `std.hash.Wyhash.hash(0, data)` (non-cryptographic, constant seed 0), used as the 0-RTT replay-cache key.

**Impact.** A chosen-input adversary can craft a distinct valid-looking 0-RTT input that collides with a legitimate ticket's 64-bit hash, causing the legitimate 0-RTT to be falsely rejected (targeted first-flight DoS); 64-bit space also invites birthday-bound accidental false-rejects at scale. It does **not** create a replay *bypass* (a true replay hashes identically and is detected); the window/capacity logic is sound.

**Remediation.** Key on a ≥128-bit cryptographic digest (e.g. SHA-256) of the full anti-replay input, or a randomly-seeded SipHash.

**Mappings.** CWE-328, CWE-407. OWASP A04.

---

### QC-14 — TLS keylog file created world-readable (Low)

**Evidence.** `src/quic/connection/methods_a.zig:20`: `linux.open(path_z, .{... .CREAT = true ...}, 0o644)` for the keylog file that receives TLS traffic secrets (lines 58-66). **Strong mitigations:** the whole path is compile-gated to Debug/test builds (`methods_a.zig:45`) and opt-in via `SSLKEYLOGFILE` (line 47); it never writes by default and is compiled out of release. Only the file *mode* is wrong.

**Remediation.** Create with `0o600`.

**Mappings.** CWE-732, CWE-312. OWASP A04.

---

### QC-15 — Interop/test cert scripts install private keys world-readable (Low)

**Evidence.** `scripts/interop_assets.sh:85-86,95-96,109-110`, `scripts/interop_local_bootstrap.sh:153-174` (incl. `chmod -R a+rX "${CERT_DIR}"`), `scripts/interop_full.sh:123-148` all `install -m 0644` EC private keys; `create_test_certs.sh:11,19,31,57` run `openssl genpkey/genrsa` with no `umask 077`/`chmod 600`. These are ephemeral localhost/interop keys, hence Low — but the same world-readable-key smell the Docker fix eliminated. (Positive reference: `interop/run_endpoint.sh` does `umask 077` + `chmod 600`.)

**Remediation.** `install -m 0600` for `*.key`/`priv.key`; `umask 077` in `create_test_certs.sh`; drop the blanket `a+rX` on key files.

**Mappings.** CWE-732. OWASP A02.

---

### QC-16 — `stateless_reset_base` derived from per-connection secret (Low)

**Evidence.** `src/quic/connection/methods_c.zig:675-691`: the reset base is `HKDF-Extract(app_tx_secret, "stateless reset base")` (or the unchecked-`getrandom` fallback at line 689, see QC-04). RFC 9000 §10.3.1 specifies a **static endpoint key** so a reset can be produced for a connection whose state was lost (crash/eviction). Tying it to per-connection state defeats that purpose. Currently Low because no outbound stateless-reset *send* path exists yet; it becomes unsound if reset emission is added.

**Remediation.** Derive the base once per endpoint from a long-lived CSPRNG-generated static key, per §10.3.1.

**Mappings.** CWE-323. OWASP A04. RFC 9000 §10.3.1.

---

### QC-17 — Nix bootstrap installer run without integrity verification (Low)

**Evidence.** `scripts/install_pkgs.sh:128-179`: `curl -fsSL https://nixos.org/nix/install -o /tmp/nix-install.$$` then `sh "$installer"`, with only shebang + `grep` string checks (lines 139-146) — no hash/signature; predictable `$$` temp name. **Mitigations:** staged to a file (not a blind `curl|sh`), prints SECURITY warnings, requires interactive confirmation unless `NONINTERACTIVE=1`/`SKIP_VERIFY=1`; dev-bootstrap tooling only.

**Remediation.** Pin and verify a known SHA-256 before executing; use `mktemp`.

**Mappings.** CWE-494, CWE-829. OWASP A08.

---

## 5. Secure Design Notes (Positive Controls Observed)

- **Slice-based production frame parser is bounds-clean.** The untrusted-UDP path is `frame.decodeOne` (zero-allocation, returns sub-slices). Every variable-length read is guarded (`if (dl.value > buf.len - i) return error.Truncated;`) before slicing; `varint.decode` errors rather than over-advancing, so `buf.len - i` never underflows; all `@intCast` are post-bounds-check; every successful decode advances ≥1 byte (no CPU spin). The reader-based `frame.decode` (with the prior alloc caps) is test-only.
- **Crypto primitives are correctly implemented.** AEAD nonce = 12-byte IV XOR big-endian, left-padded PN (`crypto_zig.zig:81-85`, `crypto_quic.zig:128-141`) — no (key, nonce) reuse on the encrypt path. HP sample offset `pn_start+4`, 16 bytes, bounds-checked against short packets (`packet.zig:359`, `crypto_quic.zig:499-505`). Retry tag derivation is fallible with ODCID/AAD size checks and compared with `std.crypto.timing_safe.eql` (`crypto_quic.zig:186-197`, `packet.zig:1309`). HKDF labels (`reset token`, `quic ku`) are RFC-correct.
- **Constant-time comparisons** on reset tokens (`conn.zig:1871`), address-token HMAC (`token.zig:167`), and Retry tags. Key material zeroed with `std.crypto.secureZero` on rotation/teardown.
- **Transport-parameter validation is real and invoked.** `TransportParams.checkLimits` (`transport_params.zig:325-369`) bounds `max_udp_payload_size ≥ 1200`, `ack_delay_exponent ≤ 20`, `max_ack_delay < 2^14`, `active_connection_id_limit ≥ 2`, `initial_max_streams_* ≤ 2^60`; decoder rejects duplicates and truncated values; invoked at `handshake_integration.zig:1407-1411` and `methods_c.zig:472-475`.
- **Receive-side stream *count* limit enforced** (`validatePeerStreamLimit`, `methods_c.zig:276-302`). CRYPTO reassembly is count-bounded to 8 fragments with no high-offset huge-allocation primitive (`conn.zig:78`). Retry-before-allocation holds. Global connection cap enforced (`incoming.zig:497`). H3 request buffering capped at 16 KiB/stream and served files at 4 MiB (`h3/server.zig:112-118,177`).
- **Default-secure binaries.** `allow_insecure` defaults `false` (`config.zig:68`); every `cmd/` client/server requires an explicit `--insecure` opt-in and prints a production warning. Keylog is release-compiled-out and env-gated. Hardened interop entrypoints (`run_endpoint.sh`) drop privileges and generate ephemeral 0600 keys.

---

## 6. Coverage Gaps and Questions

- **No `THREAT_MODEL.md` / `SECURITY_REQUIREMENTS.md`.** The de-facto requirements are the RFC 9000/9001/9002 security-considerations sections. A documented threat model (especially: is mTLS in scope; is 0-RTT enabled by default; is the DATAGRAM extension enabled by default?) would let several Medium findings be scored precisely.
- **Dynamic verification not performed.** Findings are from static tracing; QC-01/QC-02/QC-03 should be confirmed with a fuzzer/PoC harness sending crafted post-handshake frames and spoofed-source short-header packets.
- **TLS dependency internals out of scope** (tls v0.1.10). Certificate-chain validation, hostname verification, and the actual AEAD/HKDF implementations live there; this review covered only the QUIC↔TLS wiring (`handshake_integration.zig`) and the QUIC-side key schedule.
- **529 skipped tests** (GAP-0004/GAP-0013) mean advanced key-update, AEAD-limit, flow-control, and migration scenarios are not executed in CI — directly relevant to QC-01, QC-10, QC-11. Several of these findings exist *because* the behavior they would exercise is skipped.
- **`std.Random.DefaultPrng` vs `DefaultCsprng`** identity (QC-04) is asserted from stable Zig stdlib documentation and the code's own comments, not re-derived from the pinned stdlib source (the `zig env` path did not resolve in this sandbox). The distinction is not in doubt, but a maintainer can confirm against the pinned toolchain.

---

## 7. Prioritized Next Actions

1. **QC-01 (Critical) — Enforce receive-side flow control.** Add `local_max_stream_data`/`local_max_data` checks and out-of-order buffering caps in `pushStreamFrame`/`StreamRx`, raising `FLOW_CONTROL_ERROR`. Highest impact, clear fix, add the unskipped `flow_control.zig` tests as regression coverage.
2. **QC-02 + QC-03 (High) — Authenticate before migrating; count RX after decrypt.** Fix as a unit: defer `onPathAddressChanged` state changes until after AEAD verification, and move `addRxUnvalidated` after successful decrypt on the short-header path. Then harden QC-10 (source-bound, constant-time PATH_RESPONSE).
3. **QC-04 (High) — CSPRNG everywhere with checked returns.** Replace the Xoshiro CID generator with `compat.randomBytes`/`std.posix.getrandom`; wrap all 11 `getrandom` sites in a fail-closed helper.
4. **QC-05, QC-07, QC-08 (Medium) — Bound the maps/queues.** Validate stream IDs for MAX_STREAM_DATA, cap `dgram_inbox`, enforce the 2^60 MAX_STREAMS bound.
5. **QC-06 (Medium) — Token type byte + single-use Retry tokens.**
6. **QC-09, QC-11 (Medium) — Fail-closed 0-RTT header protection; rate-limit forced key updates.**
7. **QC-12–QC-17 (Low) — Hardening:** path-traversal containment in the qns endpoint; 0o600 keylog and cert-script key modes; ≥128-bit cryptographic anti-replay key; endpoint-static reset base; hash-verify the bootstrap installer.

**Closing statement.** No confirmed vulnerabilities were found in the production slice-based frame/varint parser, the AEAD/HP/Retry crypto primitives, or the default TLS posture of the client/server binaries — the prior-review fixes are intact and not regressed. The new findings concentrate in **resource-exhaustion enforcement (QC-01, QC-05, QC-07)**, **pre-authentication state transitions on the migration path (QC-02, QC-03, QC-10)**, and **randomness quality (QC-04)**. QC-01 should be treated as a release blocker.
