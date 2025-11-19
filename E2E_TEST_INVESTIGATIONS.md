# E2E Test Investigations – Snapshot

> Canonical deep-dive log lives in `E2E_TEST_INVESTIGATION.md`. Use this summary when you need the current status without wading through 2,600+ lines of notes.

## 2025-11-14 – Large-Stream 100KB+ Failures

**Status:** Phase 57 Part 10 Completed
**Failing tests:** Go comprehensive suite – Large Transfer 1MB, Multi Round-trips, Bidirectional Simultaneous, Stream Interleaving (all timing out after 30s)
**Test results:** 4/8 passing (Single Stream Echo 21B, Multiple Concurrent Streams, Large Transfer 10KB, **Large Transfer 100KB ✅**)
**Commits:** 4fac60b - congestion control fix, ec52e5a - force promotion fix, 5b3809d - HP preservation fix

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

### Phase 57 Part 10 - HP Key Preservation (✅ FIXED)

**Root Cause #3:** Header Protection (HP) keys were being rotated along with AEAD keys during key updates, violating RFC 9001 §6 behavior

**Discovery Process:**
1. After force promotion fix, 100KB test still failed with "timeout: no recent network activity"
2. Server successfully decrypted packet 100 with "hybrid HP" (CURRENT hp + NEXT AEAD)
3. Packets 101+ failed with "Header protection removal failed"
4. Analysis of quic-go reference implementation revealed HP keys must NOT rotate

**Evidence from quic-go** (`forks/quic-go/internal/handshake/updatable_aead.go:95-124`):
```go
func (a *updatableAEAD) rollKeys() {
    a.rcvAEAD = a.nextRcvAEAD      // AEAD keys ARE rotated
    a.sendAEAD = a.nextSendAEAD
    // headerDecrypter and headerEncrypter NOT updated - HP keys remain constant!
}
```

**The Issue:**
1. Packet 100 arrives with KEY_PHASE=1, successfully decrypts with CURRENT hp + NEXT AEAD
2. Server promotes keys, INCLUDING HP key from generation 0 → generation 1
3. Packet 101 arrives, still using generation 0 HP key
4. Server tries generation 1 HP key → header unprotection fails
5. Connection stalls

**Fix Implemented (Commit 5b3809d):**
Preserve CURRENT HP key during all three key update scenarios:

1. RX key promotion (incoming.zig:2138-2147):
   ```zig
   const preserved_hp = conn.app_rx_keys.?.hp;
   conn.app_rx_keys = .{ .key = next_keys.key, .iv = next_keys.iv, .hp = preserved_hp };
   ```

2. TX key sync after RX update (conn.zig:3188-3190):
   ```zig
   const preserved_hp = self.app_tx_keys.?.hp;
   self.app_tx_keys = .{ .key = next_mat.key, .iv = next_mat.iv, .hp = preserved_hp };
   ```

3. Self-initiated TX key update (conn.zig:3141-3152):
   ```zig
   const preserved_hp = self.app_tx_keys.?.hp;
   self.app_tx_keys = .{ .key = t.key, .iv = t.iv, .hp = preserved_hp };
   ```

**Verification:**
- Test results improved from 3/8 to 4/8 passing
- **100KB test now PASSES:** 102,400 bytes in 77.6ms (1.26 MB/s) ✅
- Critical milestone: First >10KB transfer working correctly

**Why HP Keys Don't Rotate:**
- HP protects packet numbers from passive observers (linkability attacks)
- NOT part of authenticated encryption (that's AEAD's job)
- Rotating HP would require peer synchronization with no security benefit
- AEAD keys rotate for forward secrecy; HP keys remain constant for simplicity

**Reference:** RFC 9001 §6, quic-go updatable_aead.go:95-124, @forks/msquic packet_space.cpp

### Previous Key Update Work (Phase 57 Parts 1-21)
- CURRENT keys decrypt up to packet number 100 with `key_phase=false`
- KEY_PHASE=1 packets at pn≥100 fail with `error.AuthenticationFailed`
- Hybrid HP approach (CURRENT hp + NEXT AEAD) implemented
- TX key sync after RX update prevents `KEY_UPDATE_ERROR`
- DCID handling improvements (length caching, reordered probes)

### Next Steps (Phase 57 Part 11+)

**Current Status:**
- ✅ 100KB test now passing (HP preservation fix successful)
- ❌ 1MB, Multiple Round-trips, Bidirectional, Stream Interleaving still failing
- 4/8 tests passing (50% success rate)

**Remaining Issues to Investigate:**
1. **1MB timeout:** Likely a second key update at higher packet count (~200-300 packets)
   - quic-go triggers key update every 64 packets or 64KB (conn.zig:3135-3136)
   - 1MB transfer would trigger multiple key updates
   - Possible issue with subsequent key rotations beyond the first update

2. **Multiple round-trips timeout:** May be related to bidirectional data flow during key updates
   - Need to verify TX key updates work correctly when client is also sending

3. **Bidirectional/Interleaving timeouts:** Complex interaction between concurrent streams and key updates
   - Possible race conditions in key promotion logic
   - Stream multiplexing during key phase transitions

**Investigation Plan:**
1. Run 1MB test with verbose logging to capture second key update behavior
2. Check if HP preservation holds for subsequent key rotations (generation 0→1→2...)
3. Verify TX/RX key sync when both peers initiate updates simultaneously
4. Add test for multiple sequential key updates (e.g., transfer 10MB to force several rotations)

**Expected Outcome:** 8/8 tests passing once all key update edge cases are handled

See `E2E_TEST_INVESTIGATION.md` for full investigation history (2,600+ lines, 10+ phases documented).

### Phase 57 Part 11 - Flow Control Investigation (🔧 IN PROGRESS)

**Date:** 2025-11-19
**Status:** 4/8 tests passing - investigating flow control issues

**Key Discoveries:**

1. **quic-go Default Window:** 512KB (`DefaultInitialMaxStreamData`)
   - Located in `forks/quic-go/internal/protocol/params.go:25`
   - Formula: `(1 << 10) * 512 = 524,288 bytes`
   - Explains why 1MB test blocks after ~974KB

2. **Transport Parameter Fix Applied (Commit 19c7668):**
   - Fixed incorrect use of MAXIMUM of all stream limits
   - Now correctly uses `initial_max_stream_data_bidi_local` for client-initiated streams
   - RFC 9000 §18.2 compliant

3. **MAX_STREAM_DATA Frame Handling Bugs Fixed (Commit ce6451a):**
   - **Bug 1:** Frames blindly overwrote values without checking if new > old (violates RFC 9000 §4.1)
   - **Bug 2:** MAX_STREAM_DATA frames were ignored if TX state didn't exist yet
   - **Fix:** Only update windows if new value is greater than current
   - **Fix:** Create TX state entry when MAX_STREAM_DATA arrives for non-existent stream
   - Added detailed `[FC-TX]` and `[FC-CONN]` logging for debugging

**Files Modified:**
- `src/quic/conn.zig:3555-3579` - Transport parameter handling
- `src/quic/endpoint/frame_handler.zig:221-269` - MAX_STREAM_DATA/MAX_DATA handlers

**Remaining Issue:**
Server respects client's 512KB limit correctly, but client isn't sending MAX_STREAM_DATA frames to expand the window for >512KB transfers. Need to verify if:
- Client is actually reading the echo data
- Window update threshold (25% in quic-go) is being reached
- MAX_STREAM_DATA frames are being sent but lost/ignored

**Commits:**
- 19c7668: Fixed transport parameter handling for flow control
- 3a1795c: Updated E2E_TEST_INVESTIGATION.md with Phase 57 Part 11 findings
- ce6451a: Fixed MAX_STREAM_DATA and MAX_DATA frame handling
- 5711b89: Documented MAX_STREAM_DATA frame handling fixes

**Next Steps:**
- Build and test with the frame handling fixes
- Add logging to track if MAX_STREAM_DATA frames are being received
- Investigate why client might not be sending window updates

**ALPN Mismatch Discovery (2025-11-19 11:37):**
- **Root Cause**: Server default ALPN "hq-interop" != Client requested "zig-quic-test"
- **Symptom**: `error.AlpnNegotiationFailed` preventing handshake completion
- **Fix**: Start server with `--alpn zig-quic-test` flag
- **Result**: Handshake completes, but transfers stall at exactly 64KB

**64KB Transfer Stall (2025-11-19 11:40):**
- **All tests stop at exactly 65536 bytes** (100KB, 1MB with 512KB window, 1MB with 2MB window)
- **Independent of window size**: Not a flow control issue
- **Independent of ALPN**: Happens with both "zig-quic-test" AND "hq-interop" ✅ Confirmed (2025-11-19 12:00)
- **Hypothesis CONFIRMED**: Key update issue at 64KB boundary (quic-go triggers updates every 64KB)
- **Test Evidence**: Ran 100KB test with "hq-interop" ALPN - still stops at 65536 bytes

**Root Cause & Fix (2025-11-19 12:06):**
- **Bug**: TX key updates used TLS "traffic upd" label instead of QUIC "quic ku" label (RFC 9001 §6)
- **Location**: `src/quic/conn.zig:3149` called `updateTrafficSecret()` instead of `updateQuicSecret()`
- **Impact**: Server derived incompatible keys → client couldn't decrypt packets after 64KB
- **Fix**: Changed to `updateQuicSecret()` (uses "quic ku" label per RFC 9001 §6)
- **Result**: ✅ **100KB test PASSES** - received all 102400 bytes, passed 64KB boundary
- **Commit**: d85a05f - Phase 57 Part 11D TX key update label fix
