# Bi-directional Streaming Progress Report - 2025-11-03

## Mission
Verify that after TLS 1.3 handshake completion, QUIC clients can bi-directionally stream data with the Zig server.

## Issues Fixed

###  1. **Handshake Packet Connection Lookup Failure** ✅ FIXED
**File**: `src/quic/endpoint.zig:2813-2840`

**Problem**: When Handshake packets arrived with empty DCID (dcid_len=0), the server couldn't find the connection in its table because the lookup used `hashBytes(dcid)` which produced a different hash than the one used when storing the connection (which had an 8-byte DCID from the Initial packet).

**Fix**: Added fallback lookup mechanism - if direct lookup fails and DCID is empty, iterate through connections to find one matching the peer address:

```zig
var c_ptr = self.conns.getPtr(key);

// Fallback: If lookup failed and DCID is empty, find connection by peer address alone
if (c_ptr == null and dcid.len == 0) {
    std.debug.print("Handshake packet has empty DCID, falling back to peer address lookup\n", .{});
    const peer_hash = hashSockaddr(&peer.storage, peer.len);
    var iter = self.conns.iterator();
    while (iter.next()) |entry| {
        if (entry.key_ptr.peer_hash == peer_hash) {
            std.debug.print("Found connection by peer address: peer_hash={x}, dcid_hash={x}\n", .{ entry.key_ptr.peer_hash, entry.key_ptr.dcid_hash });
            c_ptr = entry.value_ptr;
            break;
        }
    }
}
```

**Result**: Server can now find connections for Handshake packets with empty DCID.

### 2. **Handshake Packet Header Parsing Bug** ✅ FIXED
**File**: `src/quic/endpoint.zig:2765-2766`

**Problem**: The comment and code incorrectly claimed "Handshake packets don't have a version field" and started parsing at byte 1, skipping the 4-byte version field. This caused the parser to misinterpret version bytes as connection ID fields, resulting in `len_dec.value=0` and the server thinking packets had 0 bytes of payload.

**Before**:
```zig
// RFC 9000: Handshake packets don't have a version field, start at byte 1
var i: usize = 1;
```

**After**:
```zig
// RFC 9000 §17.2: Handshake packets DO have a version field (bytes 1-4)
var i: usize = 5; // Skip first byte (0) + version field (1-4)
```

**Result**: Handshake packets are now parsed correctly, allowing the server to decrypt them and process the client's Finished message.

## Current Status

### ✅ Working
1. **TLS 1.3 Handshake Completion**
   - Client's Finished message is received and processed
   - `updateFinishedVerified` is called with `value=true`
   - `finished_verified=true` is set on server
   - Application (1-RTT) traffic secrets are derived

   Log evidence:
   ```
   TLS: Processing Finished message
   TLS: updateFinishedVerified called: value=true, role=Server, current=false
   TLS: Set finished_verified=true
   Server: Deriving application secrets (both Finished exchanged & flushed)
   ```

2. **1-RTT Key Installation**
   - Server installs 1-RTT (Application) RX and TX keys
   - Server sends 1-RTT packets to clients (short header packets observed)

   Log evidence:
   ```
   Server: 1-RTT keys ready, our_scid=
   ```

   Client logs show:
   ```
   [TRANSPORT] Handling packet: size=40, from=127.0.0.1:4433
   [UNPACKER] Unpacking short header packet: data_len=40
   [TRANSPORT] Handling packet: size=41, from=127.0.0.1:4433
   [UNPACKER] Unpacking short header packet: data_len=41
   ```

3. **All Three Reference Clients Complete Handshake**
   - ✅ quic-go (Go)
   - ✅ aioquic (Python)
   - ✅ quinn (Rust)

### ❌ Not Working
**1-RTT Packet Reception from Clients**

**Problem**: Server receives short header (1-RTT) packets from clients but cannot process them. The stream queue remains empty - no STREAM frames are being processed.

**Evidence**:
```
DEBUG acceptStream: queue has 0 streams   # Always 0, never increases
Short header DCID bytes (after header): a9 2a 6d 0f 14 5c 38 1f ...
Looking for connection with peer_hash=b418b34fc8f6998a
Checking conn with our_scid=
```

**Diagnosis**:
- Server IS receiving 1-RTT packets (log shows "Short header DCID bytes")
- Server IS looking up connections by peer_hash
- Server IS checking connections (log shows "Checking conn with our_scid=")
- But connection lookup appears to be failing silently
- No STREAM frames are being processed
- Clients timeout waiting for responses

## Remaining Investigation

The next bug appears to be in **short header (1-RTT) packet connection lookup**. The code at `endpoint.zig:1038-1058` attempts to find the connection by:
1. Matching peer_hash
2. Comparing the packet's DCID with connection's `our_scid`

**Hypothesis**: The connection lookup is failing because:
- The DCID in client's 1-RTT packets doesn't match server's `our_scid`, OR
- The `our_scid` comparison logic has a bug, OR
- There's an issue with how DCIDs are encoded/decoded in short header packets

**Next Steps**:
1. Add detailed logging to show:
   - Full DCID from incoming 1-RTT packet
   - Full `our_scid` from each connection being checked
   - Whether they match byte-by-byte
2. Verify clients are using correct DCID (should be server's SCID from Initial response)
3. Check if there's a DCID length mismatch or encoding issue

## Files Modified

1. **`src/quic/endpoint.zig`** (2 fixes)
   - Lines 2813-2840: Handshake packet connection lookup fallback
   - Lines 2765-2766: Handshake packet header parsing correction

2. **`src/quic/tls/tls13.zig`** (diagnostic logging)
   - Lines 1572-1586: Enhanced logging in `updateFinishedVerified`

## Test Results

All three clients successfully:
- ✅ Complete Initial packet exchange
- ✅ Derive matching handshake traffic secrets
- ✅ Decrypt Handshake packets
- ✅ Process complete handshake flight (EE + Cert + CertVerify + Finished)
- ✅ Receive Finished verification from server
- ✅ Install 1-RTT keys
- ✅ Send 1-RTT packets to server
- ❌ **Receive responses from server** (timeout)

## Performance Impact

Both fixes are minimal:
- **Fix #1**: O(n) iteration through connections only when Handshake packet has empty DCID (rare)
- **Fix #2**: Correct offset calculation, no performance impact

## References

- RFC 9000 §17.2: Long Header Packets (confirms Handshake packets include version field)
- RFC 9000 §17.3: Short Header Packets (1-RTT/Application)
- RFC 9001 §4: QUIC Handshake
- RFC 8446 §4.4: TLS 1.3 Finished Message

## Summary

**Major Progress**: We've fixed critical bugs that prevented the server from:
1. Finding connections when receiving Handshake packets with empty DCID
2. Parsing Handshake packets correctly due to missing version field accounting

These fixes enabled the server to:
- Process client's Finished message ✅
- Verify handshake completion ✅
- Install 1-RTT encryption keys ✅
- Send 1-RTT packets to clients ✅

**Remaining Work**: The server needs to successfully route incoming 1-RTT packets from clients to the correct connection so it can decrypt STREAM frames and process application data.
