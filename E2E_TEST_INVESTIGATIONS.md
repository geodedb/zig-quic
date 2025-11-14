# E2E Test Investigations – Snapshot

> Canonical deep-dive log lives in `E2E_TEST_INVESTIGATION.md`. Use this summary when you need the current status without wading through 2,600+ lines of notes.

## 2025-11-14 – Large-Stream 1 MB Failures

**Status:** Active Investigation (Phase 57 Part 21)  
**Failing tests:** Go comprehensive suite – Large Transfer 1 MB, Multi Round-trips, Bidirectional Simultaneous, Stream Interleaving (all timing out after ~96 KB)  
**Primary suspect:** 1-RTT key update (KEY_PHASE flip) breaks decryption of client packets ≥ pn 100

### Findings
- CURRENT keys still decrypt up to packet number 100 with `key_phase=false`, so flow control and application I/O are no longer the bottleneck (Parts 14–15).
- The first KEY_PHASE=1 packet logs `[PHASE57-AEAD] fail pn_preview=101 … key_phase=true` even though header protection succeeded with the CURRENT hp key. AEAD immediately returns `error.AuthenticationFailed`.
- NEXT keys, which we pre-derived from the TLS key log (`key=4d105b…`, `iv=bb26da…`, `hp=afa46d…`), produce garbage packet numbers (`pn_preview≈9,560`) and bogus key-phase bits, implying the ciphertext/AAD inputs no longer line up between attempts.
- Deriving the same NEXT material via a standalone Zig helper that ingests `/tmp/tls_keys_comprehensive.log` confirms our key schedule matches quic-go’s; the mismatch must therefore originate in how we carve the ciphertext slice or manage state between CURRENT and NEXT attempts.
- Fresh instrumentation writes the first failing pn≥100 packet to `/tmp/phase57-short-header.{bin,meta}`. The new `phase57_dump_check.zig` tool replays that dump offline and shows that CURRENT keys hit `error.AuthenticationFailed` while NEXT keys corrupt the packet number length (PN reported as 4 bytes instead of the expected 2). This nails the regression down to the header-protection removal path for NEXT keys, not AEAD or key derivation.
- Hybrid replay (`CURRENT hp + NEXT AEAD`) succeeds, matching quiche/quinn’s approach of unmasking headers separately from AEAD. We ported that behaviour into `packet.decodeShortProtectedWithHp()` and log `[PHASE57-HYBRID] …` when it triggers.
- Promoting RX keys now also calls `conn.syncTxKeysAfterRxUpdate()`, ensuring ACKs leave the server with the new key phase so quic-go no longer aborts with `KEY_UPDATE_ERROR`.

### Immediate Plan
1. **Packet dump instrumentation:** Extend `packet.decodeShortProtected` to capture the complete short-header datagram (first byte, DCID, masked PN bytes, ciphertext+tag) plus metadata the first time a pn ≥ 100 decrypt fails. This replaces tcpdump/qlog requirements and keeps the investigation self-contained.
2. **Offline verifier:** Replay the dump with a minimal Zig program that reconstructs the nonce/AAD and calls the same AEAD primitives quic-go uses. This will tell us whether the runtime failure is due to slice corruption vs. header protection.
3. **Spec cross-check:** Once the failing ciphertext is reproducible offline, diff our header decryption flow against @forks/quinn and @forks/quiche to locate any divergence (sample offsets, PN slicing, AAD construction).

See `E2E_TEST_INVESTIGATION.md` §“Phase 57 Part 21” for detailed logs, commands, and next steps.

