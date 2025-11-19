# Phase 57 Part 11: Flow Control Investigation

**Date:** 2025-11-19
**Previous Status:** 4/8 tests passing after HP preservation fix (Phase 57 Part 10)
**Current Status:** 4/8 tests passing - investigating 1MB test failure

## Test Environment Setup

Added missing `updateQuicSecret` functions to vendor/ztls/src/key_schedule.zig:
- `updateQuicSecretHash` - uses "quic ku" label per RFC 9001 §6
- `updateQuicSecret` - wrapper for [32]u8 arrays
- These replace the TLS "traffic upd" label with QUIC-specific "quic ku"

## Comprehensive Test Results

```
============================================================
RESULTS: 4 passed, 4 failed, 8 total
============================================================
✅ Single Stream Echo - 21 bytes in 9.37ms
✅ Multiple Concurrent Streams - 4 streams in 9.25ms
✅ Large Transfer (10KB) - 10240 bytes in 26.51ms (0.37 MB/s)
✅ Large Transfer (100KB) - 102400 bytes in 142.40ms (0.69 MB/s)
❌ Large Transfer (1MB) - timeout: no recent network activity
❌ Multiple Round-trips - timeout: no recent network activity
❌ Bidirectional Simultaneous - timeout: no recent network activity
❌ Stream Interleaving - timeout: no recent network activity
```

## Critical Discovery: Flow Control Blocking

**Initial Hypothesis:** Second key update at higher packet count causing failure
**Actual Root Cause:** Flow control window exhaustion

### Server Log Analysis

Stream 28 (1MB test) stuck in flow control blocked state:
```
[P42-13] Stream 28 flushing 26517 pending bytes (loop 9854)
DEBUG writeStream: stream_id=28, data_len=26517, fin=false
[P42-13-FC-BLOCKED] Stream 28 still blocked, 26517 bytes pending (loop 9854)
```

### Key Observations

1. **Stream 28 State:**
   - Has 26,517 bytes pending to send
   - Cannot send due to flow control limit
   - Loops thousands of times without progress

2. **Stream 1 Behavior:**
   - Continues attempting 65536-byte writes
   - Also appears blocked

3. **No Recovery:**
   - Client not sending MAX_STREAM_DATA frames
   - Server cannot expand send window
   - Connection stalls indefinitely

## Root Cause Analysis

The 1MB test failure is **NOT** due to key update issues but rather:

1. **Flow Control Exhaustion:**
   - Stream hits flow control limit partway through 1MB transfer
   - ~974KB sent successfully, ~26KB stuck

2. **Missing Window Updates:**
   - Client (quic-go) not sending MAX_STREAM_DATA frames
   - Possible causes:
     - Client not reading/consuming data
     - MAX_STREAM_DATA generation logic broken
     - ACK processing issues preventing credit return

3. **Echo Pattern Issue:**
   - Server echo pattern may not properly trigger flow control updates
   - Need to verify server calls readStream() to consume data

## Comparison with Previous Phases

**Phase 57 Parts 1-10:** Focused on key update issues
- HP key preservation (Part 10)
- "quic ku" label fix (Part 3)
- Key promotion logic (Parts 4-9)

**Phase 57 Part 11:** Different problem domain
- Flow control window management
- MAX_STREAM_DATA frame generation
- Stream credit accounting

## Next Investigation Steps

### 1. Flow Control Configuration Check
```zig
// Current settings from Phase 54:
local_max_stream_data = 2 * 1024 * 1024;  // 2MB per stream
local_max_data = 10 * 1024 * 1024;        // 10MB connection
```
- Verify these are actually being advertised
- Check transport parameters exchange

### 2. MAX_STREAM_DATA Analysis
- Add logging for MAX_STREAM_DATA frame generation/receipt
- Verify threshold logic (1/8 window from Phase 46)
- Check if frames are being sent but lost/ignored

### 3. Server Echo Implementation
- Ensure server reads ALL data before echoing
- Verify readStream() triggers flow control updates
- Check queueIncomingStream() logic (Phase 57 Part 6 fix)

### 4. Client Behavior
- Why isn't quic-go sending window updates?
- Use Wireshark/tcpdump to verify frame flow
- Check if this is a known quic-go issue

## Hypothesis Priority

1. **Most Likely:** Server not properly consuming data in echo loop
   - Would prevent flow control credit return
   - Easy to test with additional logging

2. **Possible:** MAX_STREAM_DATA threshold too high
   - 1/8 window = 256KB threshold
   - May not trigger in time

3. **Less Likely:** Transport parameter negotiation issue
   - Would affect all large transfers
   - 100KB test works fine

## Action Items

- [x] Add detailed flow control logging
- [x] Verify server echo reads before writes
- [x] Check MAX_STREAM_DATA frame generation
- [ ] Test with different flow control windows
- [x] Compare with quic-go reference implementation

## Key Discovery: Default Flow Control Window Size

Analysis of quic-go reveals:
- Default `InitialMaxStreamData` = 512 KB (524,288 bytes)
- Located in `forks/quic-go/internal/protocol/params.go:25`
- Formula: `(1 << 10) * 512 = 1024 * 512 = 524,288 bytes`
- This explains why 1MB transfer blocks after ~974KB

## Fix Applied

Fixed transport parameter handling in `src/quic/conn.zig:3555-3579`:
- Previously: Code incorrectly took MAXIMUM of all stream data limits
- Now: Uses correct `initial_max_stream_data_bidi_local` for client-initiated streams
- RFC 9000 §18.2: `initial_max_stream_data_bidi_local` applies to locally-initiated bidirectional streams (from client's perspective)

## Remaining Issue

Client (quic-go) needs to send MAX_STREAM_DATA frames to expand window beyond initial 512KB:
1. Server can send up to 512KB (client's advertised limit)
2. For 1MB transfer, client must send MAX_STREAM_DATA to increase limit
3. Currently not happening - need to investigate why

## Summary

Phase 57 Part 11 revealed that the 1MB test failure is due to flow control exhaustion with quic-go's default 512KB stream window. The server correctly respects this limit but the client isn't sending MAX_STREAM_DATA frames to expand the window for larger transfers. This is a fundamentally different issue from the key update problems solved in Parts 1-10.
## Additional Fix: MAX_STREAM_DATA Frame Handling (ce6451a)

### Bug Discovery

Found issues in `handleMaxStreamData` and `handleMaxData`:

1. **Non-RFC-Compliant Updates:**
   - Frames were blindly overwriting values without checking if new value > old value
   - RFC 9000 §4.1: Flow control limits can only INCREASE, never decrease
   - Could lead to incorrect window reductions if stale/duplicate frames received

2. **Missing TX State Handling:**
   - If MAX_STREAM_DATA arrived before stream TX state existed, it was ignored
   - This could lose window updates for streams not yet fully initialized

### Fixes Applied

**src/quic/endpoint/frame_handler.zig:handleMaxStreamData:**
```zig
// Only update if new limit is greater
if (m.max > tx.peer_max_stream_data) {
    tx.peer_max_stream_data = m.max;
    // Log increase
} else {
    // Log ignored update
}

// Create TX state if doesn't exist
if (stream_txs.getPtr() == null) {
    stream_txs.put(stream_id, .{ .peer_max_stream_data = m.max });
}
```

**src/quic/endpoint/frame_handler.zig:handleMaxData:**
```zig
// Only update if new limit is greater
if (md.max > ctx.conn.peer_max_data) {
    ctx.conn.peer_max_data = md.max;
    // Log increase
}
```

### Impact

These fixes ensure:
- RFC-compliant flow control window updates
- No accidental window reductions from stale frames
- All MAX_STREAM_DATA updates are preserved, even for streams not yet initialized
- Better debugging with detailed logging

