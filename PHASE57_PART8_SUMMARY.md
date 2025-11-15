# Phase 57 Part 8 Summary

**Date:** 2025-11-14
**Status:** Root causes identified, partial fix implemented, core issue remains
**Finding:** Discovered TWO critical bugs preventing large transfers
**Commit:** (pending)

## Critical Findings

### Bug #1: Missing Congestion Control Check (✅ FIXED)

**Location:** `src/quic/conn.zig` writeStream function (line 2346-2354)

**Root Cause:** Server sent packets without checking `bytes_in_flight < cwnd`

**Evidence:**
Server sent 110KB when cwnd was only 15KB (7x overrun):
- PN 124: inflight=15389 > cwnd=15053 (over by 336 bytes)
- PN 125-203: Continued sending, reaching 110234 bytes inflight
- Total violation: 80 packets sent beyond congestion window
- Maximum overrun: 95181 bytes (PN 203)

**Reference Implementation:**
msquic (forks/msquic/src/core/cubic.c:189):
```c
if (Cubic->BytesInFlight >= Cubic->CongestionWindow) {
    SendAllowance = 0;  // Blocked
}
```

**Fix Implemented:**
```zig
// PHASE 57 PART 8: Check congestion control before sending (RFC 9002 §7)
// msquic: forks/msquic/src/core/cubic.c:189 - if (BytesInFlight >= CongestionWindow) SendAllowance = 0
const bytes_in_flight = self.rec.cc.bytes_in_flight;
const cwnd = self.rec.cc.cwnd;
if (bytes_in_flight >= cwnd) {
    std.debug.print("[CC-BLOCKED] bytes_in_flight={} >= cwnd={}, blocking send\n", .{ bytes_in_flight, cwnd });
    return error.CongestionControlBlocked;
}
std.debug.print("[CC-OK] bytes_in_flight={} < cwnd={}, available={}\n", .{ bytes_in_flight, cwnd, cwnd - bytes_in_flight });
```

**Result:** Server now correctly blocks sends when cwnd is full. However, tests still fail 5/8 due to Bug #2.

### Bug #2: ACK Decryption Failures Starve Congestion Window (❌ NOT FIXED)

**Root Cause:** ACK packets fail to decrypt → inflight bytes never freed → cwnd stays blocked forever

**Evidence from logs:**
```
[CC-BLOCKED] bytes_in_flight=15389 >= cwnd=15077, blocking send
[P42-13-ERROR] Stream 24 write error: error.CongestionControlBlocked (loop 587)
[PHASE57-AEAD] fail pn_preview=55373 key_phase=true ... err=error.AuthenticationFailed
[P42-13-ERROR] Stream 24 write error: error.CongestionControlBlocked (loop 588)
[P42-13-ERROR] Stream 24 write error: error.CongestionControlBlocked (loop 589)
...continues forever until timeout...
```

**Failure Chain:**
1. Server sends packets until cwnd is full (bytes_in_flight=15389, cwnd=15077)
2. Congestion control correctly blocks further sends (returns error.CongestionControlBlocked)
3. Server enters retry loop (loop 587, 588, 589, 590...593+)
4. Client sends ACK packets
5. Server receives ACKs but decryption fails (key_phase mismatch)
6. ACKs are dropped, `bytes_in_flight` never decreases
7. cwnd stays blocked, server loops forever
8. Client times out after 30 seconds

**Key Phase Mismatch:**
All failed ACK decryption attempts show:
- Incoming packets: `key_phase=true` (KEY_PHASE bit set)
- Server expects: `key_phase=false` (using CURRENT keys)
- Related to unresolved issues from Phase 57 Parts 1-6 (key update handling)

**Additional Issue: Event Loop Starvation**
- Server stuck in tight write-retry loop
- Read path not processing between retries
- Even if ACKs decrypted successfully, they wouldn't be processed timely
- Need to yield/poll between write attempts

## Test Results

### Before Fix (Phase 57 Part 7)
**Status:** 3/8 passing (max 10KB transfer)

✅ **Passing Tests:**
- Single Stream Echo (21 bytes) - 8.795ms
- Multiple Concurrent Streams (4 streams) - 7.168ms
- Large Transfer (10KB) - 10.555ms (0.93 MB/s)

❌ **Failing Tests:**
- Large Transfer (100KB) - timeout (30s)
- Large Transfer (1MB) - timeout (30s)
- Multiple Round-trips (10 cycles) - timeout (30s)
- Bidirectional Simultaneous - timeout (30s)
- Stream Interleaving (5 streams) - timeout (30s)

**Failure Mode (before fix):**
- Server violates congestion control
- Sends 110KB when cwnd is only 15KB
- Network/client overwhelmed
- Packet loss leads to timeout

### After Fix (Phase 57 Part 8)
**Status:** 3/8 passing (max 10KB transfer) - NO CHANGE

✅ **Passing Tests:** Same 3 tests
❌ **Failing Tests:** Same 5 tests (different failure mode)

**Failure Mode (after fix):**
- Congestion control correctly blocks sends
- ACK decryption fails (key phase mismatch)
- bytes_in_flight stuck, cwnd never opens
- Server loops indefinitely retrying
- Timeout after 30 seconds

**Why No Improvement:**
The congestion control fix is correct and necessary, but it exposed a deeper bug. Large transfers now fail for a different reason:
- **Before:** Network overwhelmed → packet loss → timeout
- **After:** ACK decryption fails → cwnd starved → infinite retry → timeout

## Analysis

### What We Fixed
✅ Congestion control violation (RFC 9002 §7 compliance)
✅ Prevention of network flooding
✅ Proper cwnd enforcement per msquic reference

### What Remains Broken
❌ ACK packet decryption (key phase handling from Phase 57 Parts 1-6)
❌ Event loop design (write retries starve read path)
❌ Integration between CC, key updates, and I/O

### Root Cause Chain
```
Large Transfer (100KB) Request
         ↓
Server sends ~80 packets (fills cwnd)
         ↓
Congestion Control Blocks (✅ CORRECT)
         ↓
Client sends ACKs
         ↓
ACK Decryption Fails (KEY_PHASE mismatch) ❌
         ↓
bytes_in_flight never decreases ❌
         ↓
Server stuck in write-retry loop ❌
         ↓
Read path starved, no more ACKs processed ❌
         ↓
Timeout after 30 seconds ❌
```

## Lessons Learned

1. **Congestion Control is Mandatory**
   - Every QUIC implementation MUST check `bytes_in_flight < cwnd` before sending
   - Without this check, the sender violates RFC 9002 and overwhelms the network
   - msquic, quinn, quiche all enforce this rigorously

2. **Reference Implementations are Authoritative**
   - Always check msquic/quinn/quiche for critical protocol paths
   - Their code often reveals subtle requirements not obvious from RFCs
   - Example: msquic's simple `BytesInFlight >= CongestionWindow` check

3. **Fixes Can Expose Deeper Bugs**
   - Congestion control fix is correct but revealed ACK decryption issues
   - Previously hidden by network flooding masking the key phase bug
   - Integration testing critical for multi-component fixes

4. **Event Loop Design Matters**
   - Tight write-retry loops can starve read path
   - Need balanced I/O processing even when congestion controlled
   - Consider separate read/write event handling or yield points

## Next Steps

### Priority 1: Fix ACK Decryption (Phase 57 Part 9)
**Focus:** Key phase handling and NEXT keys

**Tasks:**
1. Review Phase 57 Parts 1-6 key update implementation
2. Verify NEXT keys are properly derived and installed
3. Test KEY_PHASE bit interpretation and key selection
4. Ensure Hybrid HP approach (CURRENT hp + NEXT AEAD) works correctly
5. Add logging to show which key set successfully decrypts ACKs

**Expected Outcome:** ACKs decrypt successfully, bytes_in_flight decreases, cwnd opens

### Priority 2: Fix Event Loop Starvation (Phase 57 Part 10)
**Focus:** Balanced I/O processing

**Tasks:**
1. Identify where write retry loop blocks read path
2. Add yield/poll mechanism when congestion controlled
3. Ensure ACKs processed even when writes blocked
4. Consider event-driven architecture (epoll/kqueue)
5. Test under simulated network delay/loss

**Expected Outcome:** ACKs processed promptly even when cwnd full

### Priority 3: Integration Testing (Phase 57 Part 11+)
**Focus:** End-to-end validation

**Tasks:**
1. Verify CC + key updates work together at scale
2. Test under various network conditions (delay, loss, reordering)
3. Validate against quic-go, quinn, msquic interop tests
4. Measure throughput and latency under congestion
5. Stress test with 1MB+, multiple streams, bidirectional

**Expected Outcome:** All 8 comprehensive tests pass

## Investigation Data

### Congestion Window Violations (Before Fix)

Python analysis of server logs:
```
PN 124 VIOLATION: inflight= 15389 > cwnd= 15053 (over by    336 bytes)
PN 125 VIOLATION: inflight= 16614 > cwnd= 15053 (over by   1561 bytes)
...
PN 203 VIOLATION: inflight=110234 > cwnd= 15053 (over by  95181 bytes)
```

Total: 80 packets (PN 124-203) violated congestion control

### ACK Decryption Failures (After Fix)

Sample from server logs:
```
[PHASE57-AEAD] fail pn_preview=101 pn_len=2 pn_trunc=0x65 key_phase=true dcid_len=8 largest=100 pn_start=9 err=error.AuthenticationFailed
[PHASE57-AEAD] fail pn_preview=11404 pn_len=2 pn_trunc=0x2c8c key_phase=true dcid_len=8 largest=101 pn_start=9 err=error.AuthenticationFailed
[PHASE57-AEAD] fail pn_preview=102 pn_len=2 pn_trunc=0x66 key_phase=true dcid_len=8 largest=101 pn_start=9 err=error.AuthenticationFailed
```

All failures: `key_phase=true` in packet, server expects `key_phase=false`

### Write Retry Loop (After Fix)

Server stuck retrying:
```
[P42-13-ERROR] Stream 24 write error: error.CongestionControlBlocked (loop 587)
[P42-13] Stream 24 flushing 59536 pending bytes (loop 588)
[CC-BLOCKED] bytes_in_flight=15389 >= cwnd=15077, blocking send
[P42-13-ERROR] Stream 24 write error: error.CongestionControlBlocked (loop 588)
[P42-13] Stream 24 flushing 59536 pending bytes (loop 589)
...continues until timeout...
```

## References

- **msquic CC check:** `forks/msquic/src/core/cubic.c:189`
- **RFC 9002 §7:** Congestion Control - Validation of Bytes in Flight
- **RFC 9001 §6:** Key Update and KEY_PHASE bit handling
- **Phase 57 Part 7:** DCID optimization (PHASE57_PART7_SUMMARY.md)
- **Investigation Log:** E2E_TEST_INVESTIGATION.md
- **Code Fix:** `src/quic/conn.zig:2346-2354`

## Conclusion

**Phase 57 Part 8 Achievements:**
- ✅ Identified critical congestion control violation
- ✅ Implemented RFC 9002 §7 compliant cwnd check
- ✅ Prevented network flooding (7x overrun eliminated)
- ✅ Aligned with msquic reference implementation

**Remaining Work:**
- ❌ ACK decryption failures (key phase mismatch)
- ❌ Event loop starvation (write retries block reads)
- ❌ Integration issues (CC + key updates + I/O)
- ➡️ Requires Phase 57 Part 9+ to fix ACK processing

**Recommendation:**
The congestion control fix is correct and should be committed. However, it must be paired with fixes for ACK decryption (Phase 57 Part 9) and event loop design (Phase 57 Part 10) to fully resolve large transfer failures. The fix improves protocol compliance but doesn't yet improve test pass rate due to pre-existing bugs now exposed.
