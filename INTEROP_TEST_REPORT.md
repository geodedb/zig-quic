# QUIC Interoperability Test Report: Zig Server vs quic-go Client

**Date**: 2025-10-30
**Test Configuration**: Zig QUIC Server (127.0.0.1:4433) <-> quic-go Client
**Result**: FAILURE - Handshake timeout after 5 seconds

## Executive Summary

The quic-go client successfully completes the Initial packet exchange with the Zig server but **cannot process the coalesced Handshake packet** due to an RFC 9000 violation in the Zig server's packet coalescing logic. The server incorrectly sets the destination connection ID in the Handshake packet when coalescing it with an Initial packet, causing quic-go to reject the Handshake packet. This prevents the client from receiving the server's TLS handshake messages (ServerHello, Certificate, Finished) and results in a timeout.

---

## Test Environment Setup

### Server Configuration
- Binary: `/home/benji/src/spyder/quic/zig-out/bin/quic-server`
- Address: `127.0.0.1:4433`
- Flags: `--insecure` (skip certificate validation)
- Version: QUIC v1 (RFC 9000)

### Client Configuration
- Implementation: quic-go (Golang)
- Source: `/home/benji/src/spyder/quic/test-go-client.go`
- ALPN: `hq-interop`
- Logging: `QUIC_GO_LOG_LEVEL=debug`
- Timeout: 5 seconds

---

## Test Results Summary

**Connection Timeline:**
- Client sends Initial[0,1] with ClientHello (success)
- Server responds with coalesced Initial[1] + Handshake (partial success)
- Initial packet processed correctly
- Handshake packet REJECTED due to wrong destination connection ID
- Client times out after 5 seconds

**Root Cause:** RFC 9000 Section 12.2 violation - coalesced packets have different destination connection IDs

---

## Detailed Analysis

### Connection ID Usage

```
Client Initial:
  - Destination CID: ed85df6cdef9d482c56b9e7f2ac16ca6 (16 bytes)
  - Source CID: (empty) (0 bytes)

Server Initial Response:
  - Destination CID: (empty) (0 bytes) - CORRECT
  - Source CID: 8bd1f6093ae7540c (8 bytes)

Server Handshake (coalesced):
  - Destination CID: 8bd1f6093ae7540c (8 bytes) - WRONG! Should be (empty)
  - Source CID: 8bd1f6093ae7540c (8 bytes)
```

### Error from Client Log (line 20)

```
client coalesced packet has different destination connection ID: 8bd1f6093ae7540c, expected (empty)
```

This error repeats 7 times as the client retries.

### Why This Breaks the Handshake

RFC 9000 Section 12.2 states:
> "Senders MUST NOT coalesce QUIC packets with different connection IDs into a single UDP datagram."

The server coalesces:
1. Initial packet with DCID=(empty)
2. Handshake packet with DCID=8bd1f6093ae7540c

These have different DCIDs, violating the RFC. quic-go correctly rejects the Handshake packet, causing:
- Client never receives ServerHello/Certificate/Finished
- TLS handshake cannot complete
- Connection times out

---

## Root Cause in Code

**File**: `/home/benji/src/spyder/quic/src/quic/endpoint.zig`
**Lines**: 2213-2219

**Current (buggy) code:**
```zig
const hs_dcid = if (conn.peer_initial_scid.len > 0)
    conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len]
else
    conn.our_scid.bytes[0..conn.our_scid.len];  // BUG: Uses server's SCID
```

**Problem**: When client sends empty source CID, server uses its own SCID as DCID in Handshake packet. This is wrong.

**Expected**: When client SCID is empty, server must use empty DCID to match the Initial packet DCID.

---

## Fix Recommendation

### Option 1: Use Empty DCID (Preferred)

```zig
const hs_dcid = if (conn.peer_initial_scid.len > 0)
    conn.peer_initial_scid.bytes[0..conn.peer_initial_scid.len]
else
    &[_]u8{};  // FIXED: Use empty slice for empty client SCID
```

### Option 2: Don't Coalesce When DCIDs Would Differ

```zig
// Before coalescing, check if DCIDs match
if (initial_pkt != null) {
    const initial_dcid_empty = (conn.peer_initial_scid.len == 0);
    const handshake_dcid_would_be_nonempty = true; // Current behavior

    if (initial_dcid_empty and handshake_dcid_would_be_nonempty) {
        // Send separately to avoid DCID mismatch
        _ = try self.sendTo(conn.peer, initial_pkt.?);
        // Send Handshake in next packet
    } else {
        // Safe to coalesce
        // ... existing logic
    }
}
```

---

## Testing the Fix

1. Apply fix to `endpoint.zig`
2. Rebuild: `zig build`
3. Run test: `./run_interop_test.sh`
4. Expected: Client logs "Success!" without DCID mismatch errors

---

## Compliance Notes

### RFC 9000 Requirements

**Section 7.2** - Matching Packets to Connections:
- Destination CID in server's packets must match client's source CID
- If client SCID is empty, server must use empty DCID

**Section 12.2** - Coalescing Packets:
- All coalesced packets must have the same destination connection ID
- Receivers may reject packets with mismatched DCIDs

### Interoperability Impact

This bug affects compatibility with:
- quic-go (Golang) - **FAILS** (strict validation)
- quinn (Rust) - Likely **FAILS** (strict validation)
- quiche (Rust) - Likely **FAILS** (strict validation)
- aioquic (Python) - May work (less strict)

**Severity**: Critical - breaks handshake with major implementations

---

## Log Files

Available in: `/home/benji/src/spyder/quic/test-logs/`

- `client.log` - quic-go debug output (9.2 KB)
- `server.log` - Zig server debug output (2.7 KB)

### Key Log Excerpts

**Client - Connection Start:**
```
client Starting new connection to 127.0.0.1, source connection ID (empty),
  destination connection ID ed85df6cdef9d482c56b9e7f2ac16ca6
```

**Client - Error (repeated 7x):**
```
client coalesced packet has different destination connection ID:
  8bd1f6093ae7540c, expected (empty)
```

**Client - Timeout:**
```
Failed to dial: context deadline exceeded
```

**Server - Keys Derived:**
```
debug: deriveKeyIvHp: secret[0..4]=FDFB4505  (Handshake client)
debug: deriveKeyIvHp: secret[0..4]=53CCB36A  (Handshake server)
accepted connection
```

---

## Conclusion

**Problem**: Zig server violates RFC 9000 Section 12.2 by coalescing packets with different DCIDs

**Location**: `/home/benji/src/spyder/quic/src/quic/endpoint.zig:2218`

**Impact**: Breaks handshake with quic-go and other strict implementations

**Fix**: Use empty DCID when client SCID is empty (one-line change)

**Priority**: Critical for interoperability

---

**Report Generated**: 2025-10-30
**Test Scripts**: `/home/benji/src/spyder/quic/run_interop_test.sh`, `/home/benji/src/spyder/quic/analyze_handshake.sh`
