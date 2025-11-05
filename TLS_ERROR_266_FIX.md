# Fix for TLS Error 266 (0x010a) - Zero-Length SCID Handling

## Issue Summary

TLS Error 266 (0x010a) was affecting all QUIC clients equally. This was a server-side protocol-level issue in the QUIC/TLS handshake implementation related to improper Destination Connection ID (DCID) handling when clients use zero-length Source Connection IDs (SCIDs).

## Root Cause

According to **RFC 9000 §7.2**:
> "An endpoint that receives a packet with a zero-length Source Connection ID field MUST use a zero-length Destination Connection ID field for all packets in the connection."

The bug was in `src/quic/conn.zig` in the `shortHeaderDcid()` function (line 2629). When a client sent a zero-length SCID (`peer_initial_scid.len == 0`), the function incorrectly fell back to using `our_scid` instead of returning an empty slice:

```zig
// ❌ BEFORE (buggy code):
fn shortHeaderDcid(self: *Connection) []const u8 {
    const result = if (self.peer_initial_scid.len > 0)
        self.peer_initial_scid.bytes[0..self.peer_initial_scid.len]
    else
        self.our_scid.bytes[0..self.our_scid.len];  // BUG!
```

This caused the server to send 1-RTT (short-header) packets with a non-zero DCID when the client expected a zero-length DCID, violating RFC 9000 §7.2 and triggering TLS alert 0x010a (266) from strict QUIC implementations like quic-go.

## The Fix

Changed `src/quic/conn.zig:2631` to return an empty slice when `peer_initial_scid.len == 0`:

```zig
// ✅ AFTER (fixed code):
fn shortHeaderDcid(self: *Connection) []const u8 {
    const result = if (self.peer_initial_scid.len > 0)
        self.peer_initial_scid.bytes[0..self.peer_initial_scid.len]
    else
        &[_]u8{};  // Return empty slice per RFC 9000 §7.2
```

## Files Changed

1. **src/quic/conn.zig** (line 2625-2631)
   - Fixed `shortHeaderDcid()` to return empty slice for zero-length peer SCIDs
   - Updated documentation comments to reference RFC 9000 §7.2

2. **tests/test_zero_length_scid_1rtt.zig** (new file)
   - Comprehensive regression test for TLS Error 266
   - Tests 1-RTT packet DCID handling with zero-length peer SCID
   - Includes unit tests for `shortHeaderDcid()` function

3. **build.zig** (lines 574-582)
   - Added new test to build system
   - Test runs as part of standard test suite

## Verification

The fix ensures that:
1. Initial and Handshake packets use zero-length DCIDs (already working)
2. **1-RTT (short-header) packets use zero-length DCIDs** (this was the bug)
3. All packet types comply with RFC 9000 §7.2 requirements

## Impact

This fix resolves handshake failures with:
- quic-go clients
- Other strict QUIC implementations that enforce RFC 9000 §7.2
- Any client using zero-length SCIDs

The fix maintains backward compatibility with clients using non-zero SCIDs.

## Test Coverage

New regression test `test_zero_length_scid_1rtt.zig` includes:
1. Integration test: Full handshake with zero-length SCID client
2. Unit test: `shortHeaderDcid()` returns empty slice when `peer_initial_scid.len == 0`
3. Unit test: `shortHeaderDcid()` returns peer SCID when `peer_initial_scid.len > 0`

Existing test `test_zero_length_scid_coalescing.zig` already covered Initial and Handshake packets.
