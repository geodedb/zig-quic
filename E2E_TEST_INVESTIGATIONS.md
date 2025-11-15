# E2E Test Investigations – Snapshot

> Canonical deep-dive log lives in `E2E_TEST_INVESTIGATION.md`. Use this summary when you need the current status without wading through 2,600+ lines of notes.

## 2025-11-14 – Large-Stream 100KB+ Failures

**Status:** Phase 57 Part 8 Completed, Part 9 In Progress
**Failing tests:** Go comprehensive suite – Large Transfer 100KB, 1MB, Multi Round-trips, Bidirectional Simultaneous, Stream Interleaving (all timing out after 30s)
**Test results:** 3/8 passing (Single Stream Echo 21B, Multiple Concurrent Streams, Large Transfer 10KB)
**Commit:** 4fac60b - congestion control fix

### Phase 57 Part 8 - Congestion Control Violation (✅ FIXED)

**Root Cause #1:** Missing congestion control check in `writeStream()` (src/quic/conn.zig:2346-2354)

**Evidence:**
- Server sent 110KB when cwnd was only 15KB (7x overrun)
- Violated RFC 9002 §7 requirement: `bytes_in_flight < cwnd` before sending
- 80 packets (PN 124-203) exceeded congestion window
- Maximum overrun: 95,181 bytes at PN 203

**Fix Implemented:**
```zig
// PHASE 57 PART 8: Check congestion control before sending (RFC 9002 §7)
// msquic: forks/msquic/src/core/cubic.c:189
const bytes_in_flight = self.rec.cc.bytes_in_flight;
const cwnd = self.rec.cc.cwnd;
if (bytes_in_flight >= cwnd) {
    return error.CongestionControlBlocked;
}
```

**Reference:** @forks/msquic/src/core/cubic.c:189 - `if (BytesInFlight >= CongestionWindow) SendAllowance = 0`

### Phase 57 Part 9 - ACK Decryption Failures (❌ IN PROGRESS)

**Root Cause #2:** ACK packets fail to decrypt → bytes_in_flight never freed → cwnd stays blocked forever

**Evidence:**
```
[CC-BLOCKED] bytes_in_flight=15389 >= cwnd=15077, blocking send
[P42-13-ERROR] Stream 24 write error: error.CongestionControlBlocked (loop 587)
[PHASE57-AEAD] fail pn_preview=55373 key_phase=true ... err=error.AuthenticationFailed
[P42-13-ERROR] Stream 24 write error: error.CongestionControlBlocked (loop 588)
```

**Failure Chain:**
1. Server sends packets until cwnd full (bytes_in_flight=15389, cwnd=15077)
2. Congestion control correctly blocks further sends ✅
3. Client sends ACK packets with `key_phase=true`
4. Server attempts decryption expecting `key_phase=false` ❌
5. All ACK decryption fails → bytes_in_flight never decreases
6. Server enters infinite write-retry loop (loops 587-593+)
7. Read path starved, no ACKs processed
8. Client times out after 30 seconds

**Key Phase Mismatch:**
- All failed ACKs show `key_phase=true` (KEY_PHASE bit set)
- Server expects `key_phase=false` (using CURRENT keys)
- Related to key update implementation from Phase 57 Parts 1-6

**Additional Issue:** Event loop starvation - tight write-retry loop blocks read path

### Previous Key Update Work (Phase 57 Parts 1-21)
- CURRENT keys decrypt up to packet number 100 with `key_phase=false`
- KEY_PHASE=1 packets at pn≥100 fail with `error.AuthenticationFailed`
- Hybrid HP approach (CURRENT hp + NEXT AEAD) implemented
- TX key sync after RX update prevents `KEY_UPDATE_ERROR`
- DCID handling improvements (length caching, reordered probes)

### Immediate Plan (Phase 57 Part 9)
1. **Review key update state machine:** Check why server doesn't transition to NEXT keys when receiving `key_phase=true`
2. **Verify NEXT key installation:** Ensure NEXT keys are derived and available for decryption
3. **Fix key selection logic:** Server should try NEXT keys when KEY_PHASE bit is set
4. **Test ACK decryption:** Verify ACKs decrypt successfully, bytes_in_flight decreases
5. **Fix event loop:** Add yield/poll mechanism to prevent read path starvation

**Expected Outcome:** ACKs decrypt successfully → bytes_in_flight decreases → cwnd opens → large transfers complete

See `PHASE57_PART8_SUMMARY.md` for detailed congestion control analysis and `E2E_TEST_INVESTIGATION.md` for full investigation history.
