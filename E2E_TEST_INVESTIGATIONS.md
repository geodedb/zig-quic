# E2E Test Investigations – Snapshot

> Canonical deep-dive log lives in `E2E_TEST_INVESTIGATION.md`. Use this summary when you need the current status without wading through 2,600+ lines of notes.

## 2025-11-14 – Large-Stream 100KB+ Failures

**Status:** Phase 57 Part 9 Completed, Part 10 In Progress
**Failing tests:** Go comprehensive suite – Large Transfer 100KB, 1MB, Multi Round-trips, Bidirectional Simultaneous, Stream Interleaving (all timing out after 30s)
**Test results:** 3/8 passing (Single Stream Echo 21B, Multiple Concurrent Streams, Large Transfer 10KB)
**Commits:** 4fac60b - congestion control fix, ec52e5a - force promotion fix

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

### Phase 57 Part 9 - Force Promotion Bug (✅ FIXED)

**Root Cause #2A:** Buggy "force promotion" code prematurely flipped rx_key_phase before successfully decrypting with NEXT keys

**Evidence from logs:**
```
[PHASE57-KEY-PROMOTE] ✅ Key promotion complete  (BEFORE pn=101 processing!)
[P42-20-PN-OK] ✓ Sequential PN received: pn=101, prev_largest=100
[PHASE57-TRY] key_set=CURRENT dcid_len=8 rx_phase=true largest=100 forced=false
```

**The Bug (src/quic/endpoint/incoming.zig:1951-1961):**
Experimental code promoted keys AFTER all decryption attempts failed, not after successful NEXT key decryption:
```zig
if (!forced_attempted and conn.app_rx_next_secret != null and conn.app_rx_next_keys != null) {
    std.debug.print("[PHASE57] ⚠️ Forcing promotion to NEXT keys after repeated auth failures\n", .{});
    promoteToNextKeys(conn, conn.app_rx_next_secret.?, conn.app_rx_next_keys.?);
    return decryptShortHeaderWithKeyRotationInternal(..., true);  // Retry with forced flag
}
```

**Why It Failed:**
1. Packet 100 arrives with `key_phase=true`
2. All decryption attempts with CURRENT/NEXT/PREV keys fail (wrong DCID length, wrong HP, etc.)
3. Force promotion triggers, sets `rx_key_phase=true` BEFORE any successful decrypt
4. Packet 101 arrives, now server has `rx_key_phase=true` matching packet's `key_phase=true`
5. Server tries CURRENT keys (which are wrong generation)
6. ACK decryption fails forever

**Fix Applied (Commit ec52e5a):**
Disabled force promotion code block entirely:
```zig
// PHASE 57 PART 9: Removed buggy force promotion that was flipping rx_key_phase prematurely.
// The server should ONLY promote after successfully decrypting with NEXT keys.
// See: PHASE57_PART8_SUMMARY.md - ACK decryption failures due to premature key promotion.
```

**Result:** Still 3/8 passing (no improvement yet)

**Analysis:** Force promotion fix was necessary but not sufficient. Additional investigation revealed rx_key_phase=true at largest=100 even with force promotion disabled, suggesting another source of premature key phase modification.

### Phase 57 Part 10 - Additional Key Phase Issues (❌ IN PROGRESS)

**Discovery:** Even with force promotion disabled, rx_key_phase is set to true prematurely

**Evidence:**
```
[PHASE57-TRY] key_set=CURRENT dcid_len=8 rx_phase=true largest=100 forced=false
```

This shows `rx_key_phase=true` when processing packet at largest=100, but packet 101 is the first with `key_phase=true` from client.

**Hypothesis:**
1. Server TX key update might be triggering RX phase flip incorrectly
2. Some other code path sets rx_key_phase without successful decryption
3. Possible in conn.zig initialization code around line 3035
4. May be related to hybrid HP approach (CURRENT hp + NEXT AEAD)

**Next Steps:**
1. Search all locations that modify rx_key_phase
2. Add instrumentation to track rx_key_phase modifications with stack traces
3. Compare with msquic key update implementation
4. Fix proper key selection after promotion

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
