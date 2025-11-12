# Test Failure Investigation Log

## Date: 2025-11-11

## Issue Summary
4 server-side tests are failing with the same symptom: `ep.captureLen() == 0` (no response packets captured)

### Affected Tests
1. `test_pto_probe_zero_length_dcid`
2. `test_server_initial_response`
3. `test_zero_length_scid_coalescing`
4. `test_server_initial_processing`

## Current Understanding

### What's Working ✅
- ArrayList initialization fixed for Zig 0.15.1 compatibility
- Test capture mechanism itself works (sendTo captures when test_capture_enabled=true)
- Initial packet encryption/protection works (debug output confirms)
- Server receives and decrypts Initial packets successfully
- Endpoint role determination works ("Endpoint role determined as: .Server")

### What's Failing ❌
- Server doesn't generate ServerHello response after receiving ClientHello
- `ep.captureLen()` returns 0 (no packets queued for sending)
- `handleInitialCrypto()` processes CRYPTO frame but doesn't trigger response

### Debug Evidence

From test output:
```
Endpoint role determined as: .Server
protectPacket: pn=1 pn_len=2 header_prefix_len=21 aad_len=24
ENC aead_key: 1f 36 96 13 dd 76 d5 46 77 30 ef cb e3 b1 a2 2d
protectPacket: aeadEncrypt returned ct_len=132, plaintext.len=116
```
This shows the client Initial packet is being created correctly.

But then:
```
error: 'test_server_initial_response.test.server responds to client Initial' failed
/home/benji/src/spyder/quic/tests/test_server_initial_response.zig:66:5
    try std.testing.expect(ep.captureLen() > 0);
```

## Investigation Path

### Phase 1: Understand the Processing Flow

The flow in `processInitial()` (src/quic/endpoint/incoming.zig):
1. Parse Initial header ✅
2. Look up/create connection ✅
3. Derive Initial keys ✅
4. Decrypt packet ✅
5. Process frames (especially CRYPTO) ← **Investigation point**
6. Send ServerHello if conditions met ← **Not happening**

### Phase 2: Key Questions

1. **Is the ClientHello being processed by TLS?**
   - Check if `conn.handleInitialCrypto()` returns true
   - Check if TLS state advances

2. **Are the conditions for sending ServerHello met?**
   - Line 1028: `if (conn.role == .Server and saw_crypto and conn.crypto_tx_off_initial == 0)`
   - Need to verify all three conditions

3. **Is the handshake integration working?**
   - Check if `handshake_integration.sendServerHello()` is called
   - Check if it returns an error

## Next Investigation Steps

1. Add debug output to track:
   - Return value of `conn.handleInitialCrypto()`
   - Value of `saw_crypto` flag
   - Value of `conn.crypto_tx_off_initial`
   - Whether `sendServerHello()` is called

2. Check the ClientHello construction:
   - Verify it's a valid TLS 1.3 ClientHello
   - Check if it has all required extensions for QUIC

3. Examine TLS processing:
   - Check if TLS state machine advances properly
   - Verify server certificate/key are loaded correctly

## Hypothesis

The most likely issue is that the hand-crafted ClientHello in the test is incomplete or malformed, preventing the TLS stack from processing it correctly and generating a ServerHello response.

---
*Investigation continues below...*

## Debug Output Analysis (2025-11-11 - Part 2)

### Added Debug Output
Added debug prints to track:
1. `handleInitialCrypto()` return value and errors
2. `saw_crypto` flag state
3. ServerHello sending conditions
4. ACK packet generation

### Test Run Results

```
Server: Received Initial CRYPTO frame with 112 bytes at offset 0 (expected 0)
DEBUG: handleInitialCrypto failed with error: error.NoSignatureScheme
DEBUG: handleInitialCrypto returned ack_needed=false
DEBUG: ServerHello check: role=.Server, saw_crypto=false, crypto_tx_off_initial=0
DEBUG: ACK check: saw_crypto=false, has_initial_tx_keys=true
```

Also seeing:
```
DEBUG: handleInitialCrypto failed with error: error.MissingTransportParameters
```

## Root Cause Identified! ✅

The ClientHello in the tests is missing critical TLS extensions required for QUIC:

1. **Signature algorithms extension** (TLS Extension 13)
   - Required for TLS 1.3 to negotiate signature scheme
   - Without it: `error.NoSignatureScheme`

2. **QUIC transport parameters extension** (TLS Extension 57)
   - Required for QUIC connections (RFC 9000 §7.3)
   - Without it: `error.MissingTransportParameters`

Because these errors occur:
- `handleInitialCrypto()` returns `ack_needed=false`
- `saw_crypto` stays false
- ServerHello sending condition fails: `if (conn.role == .Server and saw_crypto and ...)`
- No response packets are generated

## Solution

Fix the `buildStandardClientHello()` function in the tests to include:
1. Signature algorithms extension ✅
2. QUIC transport parameters extension ✅
3. Any other required TLS 1.3/QUIC extensions (ALPN) ✅

This should allow the TLS handshake to proceed and generate ServerHello responses.

---

## Phase 3: ConnectionPair.connect() Failures (2025-11-11 - Part 5)

### Issue: Handshake Not Completing in Integration Tests

Several integration tests using ConnectionPair.connect() are failing:
- `RFC 9000 §17.2.4 - Handshake packet processed`
- `RFC 9000 §17.3 - Short header packets processed`
- `RFC 9002 §5 - Initial RTT measurement`
- `RFC 9000 §8.1 - Address validated after client packet`
- And others...

### Symptoms

All these tests show a similar pattern:
1. ConnectionPair.connect() starts successfully
2. Client connection is created
3. Initial packet is sent
4. But then assertions fail indicating handshake didn't complete:
   - `pn_handshake_tx` remains 0 (no Handshake packets sent)
   - `app_tx_keys` remains null (no 1-RTT keys derived)
   - `address_validated` remains false

### Root Cause Analysis

The connection establishment flow appears to be stuck after Initial packet exchange. Possible causes:
1. TLS handshake messages not being processed correctly
2. Packet exchange mechanism in test harness not delivering packets
3. Timing issues with the test polling mechanism

### Debug Findings

Added debug output to ConnectionPair.connect() revealed:
1. Server accepts connection quickly (after 1 exchange, 0ms)
2. Multiple AEAD decrypt failures occur during packet exchange:
   - `AEAD decrypt failed (auto-sample): error.AuthenticationFailed`
   - Failures happen with various packet numbers
3. The connection is established but handshake doesn't complete

### Current Status

The connection establishment mechanism is working (server accepts), but the TLS handshake isn't completing. The AEAD decrypt failures suggest issues with:
- Packet protection/unprotection in the test environment
- Key derivation or usage
- Packet number handling

### Impact

11 tests remain failing (1826 passing out of 2314 total):
- Connection tests that depend on completed handshake
- Tests checking for derived application keys
- Tests verifying handshake packet counts

---

## Second Issue Found (2025-11-11 - Part 3)

After fixing the ClientHello extensions, tests still failed with `error.MissingTransportParameters`.

### Deep Dive Analysis

The error comes from `vendor/ztls/src/tls13/context.zig:1468`:
```zig
const configured = self.config.quic_transport_parameters orelse return HandshakeError.MissingTransportParameters;
```

This is the TLS Context checking its config for transport parameters, not the Connection's parameters.

### Root Cause

The server connection creation flow had a timing issue:

**Before (broken):**
1. `createServerConnection()` called with `config.transport_params = null`
2. TLS context created WITHOUT transport parameters
3. `setupServerTransportParams()` called AFTER (too late!)
4. When processing ClientHello, TLS context has no transport params → error

**After (fixed):**
1. Generate transport parameters BEFORE calling `createServerConnection()`
2. Pass them in `config.transport_params`
3. TLS context created WITH transport parameters
4. ClientHello processing succeeds

### Attempted Fix #1

Modified `src/quic/endpoint/incoming.zig:807-855` to:
1. Generate `TransportParams` struct with proper values
2. Pass it in `ServerConnectionConfig.transport_params`
3. Remove redundant `setupServerTransportParams()` call

This didn't work due to complex memory management issues.

### Final Fix (Working!)

Modified `src/quic/endpoint/server.zig:388-410` to:
1. Only create TLS Context if transport_params is provided
2. If transport_params is null, leave tls_context as null
3. Connection falls back to TLS Engine path when tls_context is null

The key insight: When `tls_context` is null, the Connection uses the legacy TLS Engine path (`self.tls.onCryptoRecv()`), which works correctly with transport parameters set via `setLocalTransportParameters()`.

This avoids the issue where TLS Context requires transport parameters in its immutable config at creation time, by simply not creating the Context when parameters aren't available upfront.

## Results ✅

After all fixes:
- 7 more tests now pass (1842 passed, up from 1835)
- All 4 originally failing server tests now pass:
  - `test_server_initial_response`
  - `test_server_initial_processing`
  - `test_zero_length_scid_coalescing`
  - `test_pto_probe_zero_length_dcid`

The fixes required:
1. Adding missing TLS extensions to ClientHello (signature algorithms, ALPN, QUIC transport params)
2. Deferring TLS Context creation when transport parameters aren't available upfront
3. Using the TLS Engine fallback path for dynamic transport parameter scenarios

---

## Phase 2: Remaining Test Failures (2025-11-11 - Part 4)

### Issue: PacketDecryptionNotImplemented

Many integration tests were failing with `error.PacketDecryptionNotImplemented` in the packet inspector:
- RFC 9000 §7.1 - Initial packet contains CRYPTO frame
- RFC 9000 §7.2 - Server Initial contains CRYPTO frame
- And many others using ConnectionPair.connect()

### Root Cause

The `decryptInitialPacket()` function in `tests/integration/packet_inspector.zig` was not implemented. Tests need this function to decrypt and inspect packet contents for verification.

### Fix Applied

Implemented the `decryptInitialPacket()` function with:
1. Initial packet header parsing to extract DCID
2. Initial key derivation using QUIC-TLS key schedule
3. Header protection removal
4. AEAD decryption using unprotectInitialAutoSample
5. Proper role-based key selection (client vs server)

The implementation handles both QUIC v1 and v2, and correctly derives keys based on the packet's DCID.

---

## Summary of Current State (2025-11-11)

### Test Results
- **Total tests:** 2314
- **Passing:** 1826 (78.9%)
- **Failing:** 11
- **Skipped:** 477

### Key Fixes Applied
1. ✅ ArrayList API compatibility with Zig 0.15.1
2. ✅ Added missing TLS extensions to test ClientHello
3. ✅ Fixed TLS Context transport parameter initialization
4. ✅ Implemented packet decryption for packet inspector
5. ✅ Fixed compilation errors in test modules

### Remaining Issues
1. **ConnectionPair handshake completion** - Server accepts connection but TLS handshake doesn't complete, causing tests to fail on handshake assertions
2. **AEAD decrypt failures** - Multiple authentication failures during packet decryption in test environment

### Next Steps
- Investigate AEAD decrypt failures in detail
- Debug TLS handshake state machine progression
- Verify packet number space handling in tests
- Check key derivation and usage in test harness

---

## Phase 6: DCID Investigation (2025-11-11 - Part 6)

### Issue: Server Decrypt Failures with Zero-Length DCID

Investigation revealed misleading debug messages suggesting DCID was being lost during server processing. After extensive tracing:

### Findings

1. **Server correctly handles DCIDs:**
   - Original DCID is properly set when creating server connections
   - Key derivation correctly uses original_dcid (8 bytes) even when receiving packets with dcid len=0
   - The server successfully decrypts Initial packets from clients

2. **Initial ACK packets use zero-length DCID (correct per RFC):**
   - After Initial handshake, clients send ACK packets with zero-length DCID
   - This is allowed by RFC 9000 - servers can use zero-length connection IDs
   - Server correctly falls back to original_dcid for key derivation

3. **Debug output was misleading:**
   - The decryptInitialPacket function had incorrect debug output trying to extract DCID from packet bytes
   - This was showing "dcid len=0" incorrectly and causing confusion
   - Fixed by removing misleading debug messages

### Status

The DCID handling is actually working correctly. The remaining ConnectionPair.connect() failures are due to other issues in the handshake completion flow, not DCID problems.

### Test Status After DCID Investigation

- Still 1826/2314 tests passing (78.9%)
- 11 tests still failing (all related to ConnectionPair.connect() handshake completion)
- DCID handling confirmed working correctly

---

## Phase 7: Missing queueServerHandshakeFlight() Call (2025-11-11 - Part 7)

### Critical Issue Discovered

The server wasn't generating handshake messages (EncryptedExtensions, Certificate, CertificateVerify, Finished) because `queueServerHandshakeFlight()` was never being called in the current endpoint code.

### Root Cause

The TLS Engine's `maybeAutoProgress()` function deliberately returns early for servers with the comment:
```
// Let endpoint.zig handle the handshake flight via queueServerHandshakeFlight()
```

However, the current endpoint.zig was missing the call to `queueServerHandshakeFlight()`.

### Fix Applied

Added the following to `sendHandshakePackets()` in `handshake_integration.zig`:
```zig
// Server: If handshake flight not yet enqueued, queue it now
// This generates EncryptedExtensions, Certificate, CertificateVerify, Finished
if (conn.role == .Server and !conn.tls.server_handshake_flight_enqueued) {
    std.debug.print("sendHandshakePackets: Server queueing handshake flight\n", .{});
    conn.tls.queueServerHandshakeFlight();
}
```

### Progress

After this fix:
- Server now generates and sends handshake messages (115 bytes of CRYPTO data)
- Server sends coalesced Initial + Handshake packets correctly
- Server's `pn_handshake_tx` increments properly

### Remaining Issues

1. **Client not sending Handshake packets** (`pn_handshake_tx` remains 0):
   - Client successfully installs Handshake keys
   - Client's `maybeAutoProgress` shows `finished_verified=false`, indicating it hasn't verified server's Finished
   - Client is waiting to receive and verify server's Finished before sending its own

2. **Packet exchange mechanism issue**:
   - Server generates and sends handshake messages (115 bytes of CRYPTO data)
   - But client doesn't appear to be receiving or processing them
   - The loopback transport or packet delivery mechanism may have issues

3. **ConnectionPair.connect() timing**:
   - Currently only waits for server to accept connection (happens after 1 exchange)
   - Does NOT wait for handshake completion
   - Adding `waitForHandshake()` causes timeout because packets aren't being exchanged properly

### Test Status After Fix

- **1826/2314 tests passing (78.9%)**
- **11 tests still failing** (all ConnectionPair.connect() related)
- Server now correctly generates handshake messages
- Client-server packet exchange still not working correctly

---

## Summary of Fixes Applied

### ✅ Successfully Fixed Issues:
1. **ArrayList API Compatibility** - Updated to Zig 0.15.1 syntax
2. **Missing TLS Extensions** - Added signature algorithms, ALPN, transport parameters to test ClientHello
3. **TLS Context Transport Parameters** - Fixed timing issue with deferred Context creation
4. **Packet Decryption Implementation** - Implemented `decryptInitialPacket()` for packet inspector
5. **Server Handshake Messages** - Added missing `queueServerHandshakeFlight()` call

### ⚠️ Remaining Core Issue:
The fundamental issue is that the **test harness's packet exchange mechanism isn't working correctly**. While the server generates handshake messages and the client has the keys to process them, the packets aren't being delivered properly through the loopback transport. This prevents the TLS handshake from completing in integration tests.

### Recommended Next Steps:
1. Debug the loopback transport mechanism in `tests/integration/loopback.zig`
2. Verify packet delivery in `ConnectionPair.exchangePackets()`
3. Add detailed logging to track packet flow between endpoints
4. Consider if there's a buffering or timing issue in the test transport layer

---

## Phase 8: Coalesced Packet Handling & Memory Management Fixes (2025-11-12)

### Issues Discovered

1. **Coalesced packet handling missing**: Server was sending Initial+Handshake packets coalesced together (302 bytes), but `processIncomingDatagram` was only processing the first packet
2. **Double-free errors**: Both `decryptHandshakePacket` and `decryptInitialPacket` had double-free issues with errdefer + explicit free
3. **Memory leaks**: `decryptInitialPacket` had a memory leak in the PN length enumeration loop
4. **Missing build dependencies**: `packet_inspector` module was missing `quic_varint` dependency
5. **Incorrect enum values**: `packet_inspector` was using `Aes128Gcm` instead of `aes_128_gcm`

### Fixes Applied

#### 1. Coalesced Packet Handling (src/quic/endpoint.zig:775-852)
```zig
// Process all packets in the datagram (may be coalesced)
// RFC 9000 §12.2: "Senders can coalesce multiple QUIC packets into one UDP datagram"
var remaining = bytes;

while (remaining.len > 0) {
    // Parse packet length for long header packets
    var packet_len = remaining.len; // Default: entire remaining buffer

    if (remaining.len > 0) {
        const first_byte = remaining[0];
        const is_long_header = (first_byte & 0x80) != 0;

        if (is_long_header and remaining.len > 5) {
            // Parse DCID, SCID, token, and payload length
            var offset: usize = 5; // Version field

            // Parse DCID length and skip
            if (remaining.len > offset) {
                const dcid_len = remaining[offset];
                offset += 1 + @as(usize, @intCast(dcid_len));
            }

            // Parse SCID length and skip
            if (remaining.len > offset) {
                const scid_len = remaining[offset];
                offset += 1 + @as(usize, @intCast(scid_len));
            }

            // Initial packets have a token
            const packet_type = (first_byte & 0x30) >> 4;
            if (packet_type == 0 and remaining.len > offset) { // Initial
                const token_len_result = varint.decode(remaining[offset..]) catch {
                    break; // Can't parse, treat as single packet
                };
                offset += token_len_result.n;
                offset += @as(usize, @intCast(token_len_result.value)); // Skip token bytes
            }

            // Now read the packet length varint
            if (remaining.len > offset) {
                const len_result = varint.decode(remaining[offset..]) catch {
                    break; // Can't parse, treat as single packet
                };
                offset += len_result.n;
                packet_len = offset + @as(usize, @intCast(len_result.value));
                packet_len = @min(packet_len, remaining.len); // Don't exceed buffer
            }
        }
    }

    const packet_bytes = remaining[0..packet_len];
    // Process individual packet...
    remaining = remaining[packet_len..];
}
```

#### 2. Double-Free Fixes (src/quic/endpoint/incoming.zig)
- Removed explicit `allocator.free(pt_slice)` in error catch blocks (lines 705, 1499)
- Let errdefer handle memory cleanup on error returns

#### 3. Memory Leak Fix (src/quic/endpoint/incoming.zig:705)
- Re-added explicit `allocator.free(payload)` in the continue path
- `continue` doesn't trigger errdefer, so explicit free is needed when continuing the loop

#### 4. Build System Fixes (build.zig:648)
```zig
packet_inspector_mod.addImport("quic_varint", quic_varint_mod);
```

#### 5. Enum Value Fix (tests/integration/packet_inspector.zig:602)
```zig
.aes_128_gcm, // was: .Aes128Gcm
```

### Test Results After Fixes

- **Total tests:** 2348
- **Passing:** 1842 (78.5%)
- **Failing:** 21
- **Skipped:** 485
- **Memory leaks:** 0 (fixed!)

### Progress Summary

Fixed issues:
- ✅ Coalesced packet handling implemented
- ✅ Double-free errors resolved
- ✅ Memory leaks eliminated
- ✅ Build dependencies corrected
- ✅ Enum values fixed

Remaining issue:
- ⚠️ Handshake still not completing (times out after server accepts connection)
- The server accepts the connection after 1 exchange but handshake stalls
- Need to investigate why client isn't processing server's Handshake packets properly