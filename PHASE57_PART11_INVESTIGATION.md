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

- [ ] Add detailed flow control logging
- [ ] Verify server echo reads before writes
- [ ] Check MAX_STREAM_DATA frame generation
- [ ] Test with different flow control windows
- [ ] Compare with quic-go reference implementation

## Summary

Phase 57 Part 11 revealed that the 1MB test failure is due to flow control exhaustion, not key update issues. The server gets stuck with ~26KB of data it cannot send because the client hasn't provided additional flow control credit via MAX_STREAM_DATA frames. This is a fundamentally different issue from the key update problems solved in Parts 1-10.