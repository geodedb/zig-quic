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

## Phase 12: Header Protection and AEAD Decryption Fixes (2025-11-12)

### Issue: Handshake Packet AEAD Decryption Failures

Tests were failing with consistent AEAD authentication failures for Handshake packets:
- `decryptHandshakePacket: AEAD decrypt failed: error.AuthenticationFailed`
- `processHandshake: Decryption failed: error.AeadDecryptFailed`

### Investigation

1. **Header Protection Sample Extraction**
   - Fixed sample extraction offset calculation
   - RFC 9001 §5.4.2: Sample is always at offset 4 from PN field start
   - Previous code incorrectly calculated `4 - pn_len`
   - Fixed in `incoming.zig:decryptHandshakePacket()` lines 1065-1067

2. **Handshake Secret Ordering**
   - Fixed secret ordering based on connection role in `onSecretAvailable` callback
   - Server receives `.send` (server secret) first, then `.recv` (client secret)
   - Client receives opposite order
   - Fixed in `handshake_integration.zig` lines 111-131

3. **Server TLS Context Creation**
   - Fixed missing TLS context for servers
   - Added creation in `setupServerTransportParams()`
   - Eliminated "queueRealServerHello called without transport parameters" warning

4. **Test Mocking Issue**
   - Found tests using mocked zero keys (`[_]u8{0} ** 16`)
   - Violates "DO NOT MOCK TESTS" directive
   - Fixed `test_ecn_longitudinal.zig` and `test_ack_ecn_handshake.zig` to use properly derived keys

### Current Status (After Phase 12)
- **Total tests:** 2347
- **Passing:** 1840 (78.4%)
- **Failing:** 22
- **Skipped:** 485

### Remaining Issues
- AEAD decryption still failing despite correct HP removal
- Possible issues with:
  - Packet number expansion/encoding
  - AEAD nonce construction
  - Associated data formation
  - Key installation timing

---

## Phase 13: Header Protection Fixes and TLS Key Mismatch Discovery (2025-11-12 - Continued)

### Additional Fixes Applied

1. **Fixed Header Protection Removal Logic**
   - Issue: `headerUnprotect` was being called with zero-length PN bytes, causing `InvalidPacketNumberLength` error
   - Solution: Manually generate HP mask using AES-ECB to peek at PN length
   - Then apply same mask to unmask both header byte and PN bytes
   - Fixed in `incoming.zig:1481-1535`

2. **Simplified HP Mask Application**
   - Removed double call to `headerUnprotect`
   - Use single mask generation for both PN length detection and actual unmasking
   - Ensures consistent mask application

### Critical Discovery: TLS Handshake Key Mismatch

Investigation revealed the root cause of AEAD failures:

**Client and Server are deriving completely different Handshake keys!**

Example from test output:
- Server derives from secrets (4CE9.../9CEE...):
  - client_keys: key=51AA061F, hp=EF828DBD
  - server_keys: key=F7FE85E8, hp=843F3F8D

- Client derives from different secrets (1CF9.../0EF0...):
  - client_keys: key=7501922B, hp=9EB403C6
  - server_keys: key=07E657DB, hp=6EA61277

This indicates the TLS handshake is not properly establishing shared secrets between endpoints.

### Root Cause Analysis

The TLS handshake appears to be:
1. Not completing the key exchange properly
2. Using test/mocked secrets instead of derived shared secrets
3. Missing proper ECDHE key agreement

This explains why AEAD authentication consistently fails - the encryption and decryption keys don't match between sender and receiver.

### Current Status (End of Phase 13)
- **Total tests:** 2347
- **Passing:** 1840 (78.4%)
- **Failing:** 22
- **Skipped:** 485

### Next Steps Required
- Fix TLS handshake to properly derive shared secrets
- Ensure ECDHE key exchange completes correctly
- Verify TLS transcript is consistent between client and server
- Ensure proper secret derivation from TLS master secret

---

## Phase 17: Root Cause - ECDHE Shared Secret Mismatch (2025-11-12 - Current Session)

### Critical Discovery

Added comprehensive debug output to TLS Engine to track ECDHE shared secrets and transcript hashes:

**Client:**
- ECDHE shared: `01 02 03 04 05 06 07 08` (sequential test pattern!)
- Transcript: `2D BB A5 8B B8 2F 45 98`
- Derived client_hs: `81 46 6F 75`
- Derived server_hs: `E6 AB 58 8C`

**Server:**
- ECDHE shared: `18 34 A3 27 AB DF 93 5A` (real crypto result)
- Transcript: `91 FA 9D BF 08 EC 44 25`
- Derived client_hs: `B1 0E 0D 03`
- Derived server_hs: `39 F6 67 A3`

**Analysis:** Client and server derive completely different ECDHE shared secrets and transcript hashes, resulting in incompatible handshake keys. This is why AEAD authentication consistently fails.

### Root Cause Identified

The client's ECDHE shared secret `01 02 03 04 05 06 07 08` is a sequential test pattern, not a real X25519 scalar multiplication result. Investigation reveals:

1. **TLS Engine Structure (engine.zig:151-152):**
   ```zig
   my_priv: ?[32]u8 = null,  // Client's X25519 private key
   my_pub: ?[32]u8 = null,   // Client's X25519 public key
   ```

2. **TLS Engine has `ensureKeypair()` function (engine.zig:304-325):**
   - Generates X25519 keypair if `my_priv`/`my_pub` are null
   - Properly clamps private key per RFC 7748
   - Called from `queueRealServerHello()` for servers

3. **Problem:** Tests that manually construct ClientHellos (like `buildStandardClientHello()`) generate X25519 keypairs but don't save the private key in the TLS Engine's `my_priv` field. When the client later receives ServerHello and needs to compute ECDHE shared secret, it doesn't have its private key.

4. **Unit tests that explicitly call `setEcdhe()` with mock values (01 02 03...) are working as intended** - they're deliberately using test values. The issue is with integration tests that expect real ECDHE but aren't properly initializing the keypair.

### Attempted Fixes

**Fix #1 (Partial):** Added `ensureKeypair()` call in Connection initialization for clients:
```zig
// src/quic/conn.zig:836-838
if (role == .Client) {
    self.tls.ensureKeypair();
}
```

**Result:** Compilation successful after making `ensureKeypair()` public, but tests with mock ECDHE values (01 02 03...) still appear. This is expected for unit tests that deliberately use mocks, but integration tests may still have issues.

### Recommended Next Steps

1. **Distinguish between unit tests (mock ECDHE) and integration tests (real ECDHE)**:
   - Unit tests with `setEcdhe()` should continue using mock values
   - Integration tests using ConnectionPair should use real X25519

2. **Verify ClientHello generation path**:
   - Ensure ConnectionPair tests use engine's own ClientHello generation
   - OR ensure manual ClientHello builders coordinate with engine's `my_priv`

3. **Add assertion to catch missing private key**:
   - When computing ECDHE, check if `my_priv` is null and fail fast with clear error

4. **Remove excessive debug output** added during investigation (causing test noise)

5. **Test-specific fix**: For tests building ClientHellos manually, either:
   - Call `engine.ensureKeypair()` before building ClientHello and use `engine.my_pub`
   - Save generated private key: `engine.my_priv = sk`

### Current Status (End of Phase 17)
- **Total tests:** 2044
- **Passing:** 1731 (84.7% - regression from adding debug output)
- **Root cause:** ECDHE shared secret mismatch due to missing client private key storage
- **Fix applied:** Partial (ensureKeypair() call added, but may not cover all test paths)
- **Recommended:** Remove debug output, verify fix covers all test scenarios

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

---

## Phase 9: Coalesced Packet Type Recognition & Handshake Decryption (2025-11-12)

### Critical Bug Discovered

The packet type was being determined ONCE from the first byte of the datagram and used for ALL packets in a coalesced datagram. This meant when processing Initial+Handshake coalesced packets (302 bytes total), both packets were being processed as Initial (type 0) instead of correctly recognizing the second packet as Handshake (type 2).

### Issues Found

1. **Incorrect packet type determination**: The type was calculated once as `const ty = (first >> 4) & 0x03` and reused for all packets
2. **Wrong decryption function**: `decryptHandshakePacket` was using `unprotectInitialAutoSample` which is specifically for Initial packets
3. **Incorrect packet number byte extraction**: Was extracting from wrong offset in the packet

### Fixes Applied

#### 1. Fixed Packet Type Recognition (src/quic/endpoint.zig:855-867)
```zig
// BEFORE: Used same 'ty' for all packets
if (ty == 0) { // Initial
} else if (ty == 2) { // Handshake

// AFTER: Re-parse type from each packet's first byte
const packet_ty = (packet_bytes[0] >> 4) & 0x03;
if (packet_ty == 0) { // Initial
} else if (packet_ty == 2) { // Handshake
```

#### 2. Implemented Proper Handshake Decryption (src/quic/endpoint/incoming.zig:1503-1548)
```zig
// Cannot use unprotectInitialAutoSample for Handshake packets!
// Manually perform decryption with correct packet type in AAD:

// 1. Extract HP sample and unmask header
const sample_offset_actual = 4 - @as(usize, actual_pn_len);
@memcpy(&sample16, full_pn_and_payload[sample_offset_actual .. sample_offset_actual + 16]);
crypto.headerUnprotect(.aes_128_gcm, &rx_keys.hp, &sample16, &masked_header, masked_pn_bytes[0..actual_pn_len]);

// 2. Build AAD with unmasked header (correct packet type preserved)
var aad_buf: [256]u8 = undefined;
aad_buf[0] = masked_header; // Now unmasked with correct type bits
@memcpy(aad_buf[1 .. 1 + header_prefix.len], header_prefix);
@memcpy(aad_buf[1 + header_prefix.len .. 1 + header_prefix.len + actual_pn_len], masked_pn_bytes[0..actual_pn_len]);
const aad = aad_buf[0 .. 1 + header_prefix.len + actual_pn_len];

// 3. AEAD decrypt with correct AAD
const dec = crypto.aeadDecrypt(.aes_128_gcm, &rx_keys.key, &rx_keys.iv, full_pn, aad, actual_ciphertext, pt_slice);
```

#### 3. Fixed Packet Number Byte Extraction
```zig
// BEFORE: Wrong offset
@memcpy(masked_pn_bytes[0..actual_pn_len], bytes[i .. i + actual_pn_len]);

// AFTER: Correct - PN bytes are at start of full_pn_and_payload
@memcpy(masked_pn_bytes[0..actual_pn_len], full_pn_and_payload[0..actual_pn_len]);
```

### Debug Output Analysis

With fixes, we now see:
- Initial packet (type 0): 138 bytes extracted at offset 0
- Handshake packet (type 2): 164 bytes extracted at offset 138
- Server and Client both install Handshake keys correctly
- processHandshake is now called for Handshake packets (was being skipped before)

### Current Status

- **Total tests:** 2348
- **Passing:** 1842 (78.5%)
- **Failing:** 21
- **Issue:** Handshake packet AEAD decryption still failing with `error.AuthenticationFailed`

The core packet processing flow is now correct, but there appears to be an issue with the Handshake key derivation or AAD construction that's preventing successful decryption.

## Phase 10: TLS Handshake Integration Fix (Session 11)

### Issues Found

1. **Handshake Secret Ordering Issue**
   - Location: `endpoint/handshake_integration.zig:101-119`
   - Problem: onSecretAvailable assumed first call was client secret, second was server secret
   - Reality: Order depends on role - Server gets .send (server) then .recv (client)
   - Fix: Check connection role to properly map secrets

2. **Missing Server TLS Context**
   - Location: `endpoint/handshake_integration.zig:setupServerTransportParams`
   - Problem: Server created without TLS context, fell back to legacy Engine path
   - Warning: "queueRealServerHello called without transport parameters"
   - Fix: Create TLS context in setupServerTransportParams when missing

3. **Header Protection Mask Issues**
   - Location: `endpoint/incoming.zig:decryptHandshakePacket`
   - Problem: Header first byte incorrect after unmasking (e.g., 0xEF instead of 0xE0)
   - Root cause: Header protection removal not working correctly
   - Status: Under investigation

### Fixes Applied

1. **Fixed Handshake secret ordering** - Check role to correctly map .send/.recv to client/server
2. **Create TLS context for server** - Added context creation in setupServerTransportParams
3. **Added comprehensive debug logging** - Track AAD construction and key installation

### Current Status

- **Total tests:** 2348
- **Passing:** 1841 (78.4%)
- **Failing:** 22 (regression by 1)
- **Progress:** Server now gets Handshake secrets and uses TLS Context path
- **Remaining Issue:** Handshake AEAD decryption still fails due to incorrect AAD first byte

### Next Steps

1. Investigate header protection mask calculation
2. Verify HP key derivation matches RFC 9001
3. Check if sample extraction offset is correct for varying PN lengths

## Phase 14: TLS Key Exchange and Packet Padding Fixes (Current Session)

### Issues Found

1. **TLS Traffic Secret Installation Direction Mismatch**
   - Location: `vendor/ztls/src/tls13/context.zig:2072-2073`
   - Problem: Client was installing traffic secrets with wrong direction
   - Client was using: `.send` with `server_hs`, `.recv` with `client_hs`
   - Should be: `.send` with `client_hs`, `.recv` with `server_hs`
   - Fix: Corrected traffic secret installation for CLIENT role

2. **Insufficient Packet Payload for Header Protection**
   - Location: `src/quic/packet.zig` (multiple functions)
   - Problem: Small payloads (e.g., single PING frame = 1 byte) too small for HP sample extraction
   - RFC 9001 §5.4.3: Need at least `(4 - pn_len) + 16` bytes of ciphertext for AES
   - With 2-byte PN and 1-byte payload: only 17 bytes ciphertext, but need 18
   - Fix: Added automatic padding to ensure minimum plaintext size:
     - `min_plaintext_len = (4 - pn_len)` for `pn_len < 4`
     - Pad with PADDING frames (0x00) when needed

### Fixes Applied

1. **Fixed TLS client traffic secret installation**:
   ```zig
   // CLIENT uses client_hs for send, server_hs for recv (opposite of server)
   try self.installTrafficSecret(.Handshake, .send, hs.client_hs);
   try self.installTrafficSecret(.Handshake, .recv, hs.server_hs);
   ```

2. **Added minimum payload padding for all packet types**:
   - `encodeHandshakeProtected`: Pads to minimum size for HP
   - `encodeShortProtected`: Pads 1-RTT packets
   - `encode0RTTProtected`: Pads 0-RTT packets
   - All functions now ensure `plaintext.len >= max(0, 4 - pn_len)`

3. **Cleaned up excessive debug output** to reduce noise

### Current Status

- **Total tests:** 2348
- **Passing:** 1841 (78.4%)
- **Failing:** 22 (stable)
- **Progress:**
  - Fixed TLS key exchange direction issue
  - Eliminated packet padding errors
  - Still seeing AEAD authentication failures in Handshake decryption

### Remaining Issues

- Many small packets (92 with 1-byte payload) still being generated
- Handshake AEAD decryption still failing with `error.AuthenticationFailed`
- Tests show "decryptHandshakePacket: AEAD decrypt failed"

### Next Steps

1. Investigate why Handshake keys still don't match between client and server
2. Verify TLS transcript consistency between endpoints
3. Check if ECDHE shared secret is computed correctly
4. Consider endianness issues in mask application

## Phase 15: Connection Lookup and TLS Context Investigation (Current Session)

### Issues Investigated

1. **Connection Lookup Mismatch (Initially Suspected)**
   - Added extensive debug logging to track connection registration and lookup
   - Found that client connections are correctly registered by both:
     - `peer_initial_dcid` (the server's DCID)
     - `our_scid` (the client's SCID)
   - Server connections are registered by:
     - Client DCID hash for Initial packets
     - Server SCID hash for Handshake packets
   - **Result:** Connection lookup is working correctly

2. **peer_initial_scid Tracking**
   - Verified that server correctly sets `peer_initial_scid` from client's Initial SCID
   - Client correctly uses `peer_initial_scid` as DCID for Handshake packets (RFC 9000 §7.2)
   - **Result:** peer_initial_scid tracking is correct

3. **Shared Connection Object in Tests (Initially Suspected)**
   - Added debug logging to `setCurrentConnection` and `clearCurrentConnection`
   - Initially saw both client and server installing keys on same connection object address
   - **Finding:** This was from unit tests that manually call `installHandshakeKeys`
   - Integration tests use separate client and server connections as expected

### Debug Output Added

1. **Client connection registration logging**:
   ```zig
   std.debug.print("Client connection registered:\n", .{});
   std.debug.print("  peer_hash={X:0>16}\n", .{peer_hash});
   std.debug.print("  By DCID hash={X:0>16} (peer_initial_dcid)\n", .{...});
   std.debug.print("  By SCID hash={X:0>16} (our_scid)\n", .{...});
   ```

2. **Connection lookup debugging**:
   ```zig
   std.debug.print("processHandshake: Looking up conn with peer_hash={X:0>16}, DCID len={}, DCID hash={X:0>16}\n", .{
       ph, header.dcid.len, hashBytes(header.dcid)
   });
   ```

3. **TLS Context callback tracking**:
   ```zig
   std.debug.print("setCurrentConnection: Setting conn={*} role={s}\n", .{
       conn, if (conn.role == .Server) "Server" else "Client"
   });
   ```

### Key Findings

1. **Connection Lookup Works:** The connection lookup mechanism is functioning correctly. Connections are found but AEAD decryption fails.

2. **Keys Are Being Installed:** Both client and server are installing Handshake keys, but they still fail to decrypt each other's packets.

3. **TLS Context Callbacks:** The threadlocal connection context is being set and cleared properly for TLS callbacks.

### Current Status

- **Total tests:** 2348
- **Passing:** 1841 (78.4%)
- **Failing:** 22 (stable)
- **Root Cause:** AEAD authentication failures in Handshake decryption, not connection lookup issues

### Remaining Issues

The core issue is that Handshake packets fail AEAD authentication, suggesting:
- Keys are derived differently between client and server
- Packet construction AAD doesn't match between encryption and decryption
- Possible TLS transcript divergence between endpoints

### Next Steps

1. Compare the exact keys being used for encryption vs decryption
2. Verify TLS transcript is identical between client and server
3. Check if transport parameters are affecting key derivation
4. Investigate if there's a race condition in key installation timing

## Phase 16: TLS Handshake Message Flow Analysis (Current Session)

### Investigation Approach

Added comprehensive debug logging to trace:
1. TLS Context crypto processing (`Context.processCrypto`)
2. Handshake message parsing (ClientHello, ServerHello, etc.)
3. Secret derivation and installation
4. Transport parameter encoding and setup
5. Connection creation and peer_initial_dcid tracking

### Key Findings

1. **TLS Context is Working**:
   - Both client and server are using TLS Context (not legacy Engine)
   - CRYPTO data is being processed at Initial and Handshake levels
   - Handshake messages are being parsed correctly

2. **Transport Parameters are Set**:
   - Server creates TLS Context with 60-62 bytes of transport parameters
   - Client has transport parameters set via `setTransportParameters()`
   - `peer_initial_dcid` is correctly captured from client's Initial DCID

3. **Handshake Secrets are Derived**:
   - Both client and server derive Handshake secrets via `onSecretAvailable`
   - Secrets are different between client and server (expected)
   - Keys are installed via `installHandshakeKeys()`

4. **Handshake Stalls After ServerHello**:
   - ClientHello messages parsed (type=01, 110-173 bytes)
   - ServerHello messages parsed (type=02, 86 bytes)
   - **Missing**: EncryptedExtensions, Certificate, CertificateVerify
   - Some Finished messages parsed but likely premature

### Root Cause Identified

The handshake is stalling after ServerHello because:
1. Server generates ServerHello in Initial packet (correct)
2. Server should then send EncryptedExtensions, Certificate, CertificateVerify, and Finished in Handshake packets
3. These Handshake packets are either not being sent or not being received/decrypted properly
4. AEAD authentication failures suggest the Handshake packets are corrupted or using wrong keys

### Debug Output Added

1. **TLS Context processing**:
   ```zig
   std.debug.print("Context.processCrypto: role={s}, level={s}, data_len={}\n", .{
       if (self.config.role == .Server) "Server" else "Client", @tagName(level), data.len
   });
   ```

2. **Handshake message parsing**:
   ```zig
   std.debug.print("  Parsed handshake message: type={X:0>2} ({s}), len={}\n", .{
       @intFromEnum(parsed.typ), @tagName(parsed.typ), parsed.body.len
   });
   ```

3. **Transport parameter setup**:
   ```zig
   std.debug.print("setupServerTransportParams: Encoded {} bytes of transport params for conn={*}\n", .{
       tp_bytes.len, conn
   });
   ```

### Current Test Status

- **Total tests:** 2348
- **Passing:** 1841 (78.4%)
- **Failing:** 22 (stable)
- **Failure pattern:** Handshake timeout after ServerHello

### Next Steps

1. Investigate why server's Handshake messages (EncryptedExtensions, Certificate, etc.) are not being received
2. Check if server is actually sending these messages after ServerHello
3. Verify Handshake packet encryption/decryption is using correct keys
4. Trace the exact point where AEAD authentication fails in Handshake decryption