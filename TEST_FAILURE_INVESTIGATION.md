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