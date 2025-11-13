# E2E Test Investigation Log

This document tracks investigations and fixes for end-to-end interoperability tests with quic-go, quinn, and other QUIC implementations.

---

## Phase 38: Packet Number Expansion Bug (RESOLVED ✅)

**Date:** 2025-11-13
**Test:** `make e2e-test-go-comprehensive`
**Initial Error:** `PROTOCOL_VIOLATION (local): received ACK for an unsent packet`

### Problem Description

The quic-go client was rejecting the Zig server's ACK frames with "received ACK for an unsent packet" error. The client sent packets 0, 1, 2, 3, ... but the server was acknowledging incorrect packet numbers.

### Root Cause Analysis

**Two bugs discovered:**

1. **Bitmap Tracking Bug** (src/quic/endpoint/incoming.zig:978)
   - Code was directly assigning to `pn_initial.max` and `pn_initial.have_any`
   - This bypassed the `track()` method which updates the sliding window bitmap
   - Result: Only the most recent packet was tracked, no contiguous ranges

2. **Return Value Bug** (src/quic/crypto_quic.zig:434, 529-538) ⭐ **CRITICAL**
   - `unprotectInitialAutoSample()` was returning the WRONG value!
   - Function signature: `pub fn unprotectInitialAutoSample(...) !usize`
   - Returned: `aeadDecrypt()` result (plaintext length, e.g., 1240 bytes)
   - Should return: Expanded packet number (e.g., 0)

   **Debug Evidence:**
   ```
   [unprotectInitial] truncated=0 -> expanded to full_pn=0  ✅ Correct!
   [processInitial] After decrypt: packet_number=1240      ❌ WRONG!
   ```

   **What happened:**
   - Client sent packet 0 (PN bytes: 00 00)
   - Server correctly expanded truncated PN to 0
   - `aeadDecrypt()` returned 1240 (plaintext length)
   - Function returned 1240 as the packet number
   - Server sent ACK for packet 1240
   - Client rejected: "received ACK for an unsent packet"

### The Complete Fix

**Part 1: Fix Bitmap Tracking** (src/quic/endpoint/incoming.zig:978)
```zig
// BEFORE (WRONG):
conn.pn_initial.max = decrypted.packet_number;
conn.pn_initial.have_any = true;

// AFTER (CORRECT):
conn.trackRecvPnInitial(decrypted.packet_number);
```

**Part 2: Fix Return Value** (src/quic/crypto_quic.zig:434, 529-538)
```zig
// Changed function signature:
pub fn unprotectInitialAutoSample(...) !u64 {  // Was: !usize

// Changed return logic:
_ = aeadDecrypt(...) catch |err| {
    if (full_pn > 0 and full_pn < 1000) {
        std.debug.print("AEAD decrypt failed: pn={} err={}\n", .{ full_pn, err });
    }
    return err;
};

// Return the expanded packet number, NOT the plaintext length
return full_pn;
```

### Verification

After fix, packet numbers are correctly expanded:
```
[unprotectInitial] truncated=0 -> expanded to full_pn=0
[processInitial] After decrypt: packet_number=0  ✅

[unprotectInitial] truncated=1 -> expanded to full_pn=1
[processInitial] After decrypt: packet_number=1  ✅
```

**Result:**
- ✅ No more "received ACK for an unsent packet" errors
- ✅ Packet numbers: 0, 1, 2, 3, 4, ... (correct sequence)
- ✅ ACK frames acknowledge correct packet numbers

**Phase 38 Status:** ✅ **RESOLVED**

---

## Phase 39: TLS UnexpectedAlgorithm Error (IN PROGRESS 🔄)

**Date:** 2025-11-13
**Test:** `make e2e-test-go-comprehensive`
**Error:** `timeout: no recent network activity`
**Root Cause:** `error.UnexpectedAlgorithm` preventing ServerHello transmission

### Problem Description

After fixing Phase 38, the test now times out instead of showing a protocol violation. The server never sends ServerHello to the client, causing the client to retransmit and eventually timeout.

### Investigation Timeline

**Observation 1: ServerHello Not Being Sent**

Log shows:
```
[processInitial] Checking ServerHello condition: role=Server, saw_crypto=true
[processInitial] Attempting to send ServerHello...
sendServerHello: Context has no Initial CRYPTO data
```

After first CRYPTO frame, ServerHello is attempted but TLS context has no data yet (ClientHello incomplete).

**Observation 2: Fragmented ClientHello**

The ClientHello is split across two Initial packets:
- Packet 0: 1232 bytes at offset 0
- Packet 1: 264 bytes at offset 1232
- Total: 1496 bytes

**Observation 3: Error After Second Packet**

```
Server: Received Initial CRYPTO frame with 264 bytes at offset 1232 (expected 1232)
processInitial: handleInitialCrypto error: error.UnexpectedAlgorithm  ⚠️
[processInitial] Checking ServerHello condition: role=Server, saw_crypto=false
```

The error causes `handleInitialCrypto()` to return `false`, which prevents `sendServerHello()` from being called!

### Root Cause

**The Sequence:**
1. Packet 0 arrives → First 1232 bytes of ClientHello → Incomplete
2. `sendServerHello()` called → No TLS data available yet (ClientHello not complete)
3. Packet 1 arrives → Completes ClientHello (1232+264=1496 bytes)
4. `handleInitialCrypto()` processes CRYPTO data:
   - ✅ TLS context successfully parses complete ClientHello
   - ✅ Handshake secrets derived and installed
   - ❌ `error.UnexpectedAlgorithm` thrown from TLS layer
5. Error caught → `handleInitialCrypto()` returns `false`
6. `saw_crypto` remains `false` → `sendServerHello()` NOT called
7. Client never receives ServerHello → Retransmits → Timeout

**Debug Evidence:**
```
# TLS processing succeeds:
  Parsed handshake message: type=01 (client_hello), len=1493
onSecretAvailable: conn=... role=Server level=Handshake secret[0..4]=815087B8
installHandshakeKeys: CALLED with role=Server
installHandshakeKeys: Server installed Handshake keys  ✅

# But then error prevents continuation:
processInitial: handleInitialCrypto error: error.UnexpectedAlgorithm  ❌
```

### Code Analysis

**Error Location Chain:**
1. `incoming.zig:1015`: `conn.handleInitialCrypto()` called
2. `conn.zig:1668`: Delegates to `handleCryptoFrameGeneric()`
3. `conn.zig:1430`: Calls `tls_ctx.processCrypto(level, hs)`
4. `vendor/ztls/src/tls13/context.zig`: Processes TLS handshake messages
5. Somewhere in TLS processing: `error.UnexpectedAlgorithm` thrown

**Possible Sources** (from grep results):
- `vendor/ztls/src/sig.zig`: Signature algorithm parsing (ECDSA, RSA, Ed25519)
- `vendor/ztls/src/x509.zig`: Certificate key algorithm detection
- `vendor/ztls/src/tls13/context.zig:1821`: `selectServerSignatureScheme()` call

**The Paradox:**
- Handshake keys ARE successfully installed (line 1882-1883 in driveServerHandshakeFlight)
- This means ClientHello was parsed successfully
- Yet `error.UnexpectedAlgorithm` is still thrown
- This suggests the error occurs AFTER key installation, possibly during certificate/signature processing

### Fixes Applied

**Fix 1: Remove Early Exit Condition** (src/quic/endpoint/incoming.zig:1061)
```zig
// BEFORE:
if (conn.role == .Server and saw_crypto and conn.crypto_tx_off_initial == 0) {

// AFTER:
if (conn.role == .Server and saw_crypto) {
```
**Rationale:** Try sending ServerHello after EVERY CRYPTO frame, not just the first one. Handles fragmented ClientHello scenarios.

**Fix 2: Add Error Logging** (src/quic/endpoint/incoming.zig:1019)
```zig
} catch |err| blk: {
    std.debug.print("processInitial: handleInitialCrypto error: {}\n", .{err});
    break :blk false;
};
```
**Rationale:** Identify what error is preventing the handshake from progressing.

### Current Status

**Diagnosis:**
- ✅ Identified error: `UnexpectedAlgorithm` in TLS processing
- ✅ Error prevents `handleInitialCrypto()` from returning success
- ✅ This blocks ServerHello transmission
- 🔄 Need to trace exact error source in vendor/ztls
- 🔄 Need to determine if error is fatal or can be handled gracefully

**Next Steps:**
1. Add detailed logging in `vendor/ztls/src/tls13/context.zig:driveServerHandshakeFlight()`
2. Trace `selectServerSignatureScheme()` execution
3. Check certificate/key format compatibility
4. Determine if error occurs during signature scheme negotiation or certificate parsing
5. Fix underlying issue or improve error handling to allow handshake continuation

**Phase 39 Status:** 🔄 **IN PROGRESS**

---

## Summary

| Phase | Issue | Status | Files Modified |
|-------|-------|--------|----------------|
| 38 | Packet number expansion returning wrong value | ✅ RESOLVED | crypto_quic.zig, incoming.zig |
| 39 | UnexpectedAlgorithm error blocking ServerHello | 🔄 IN PROGRESS | incoming.zig (partial fix) |

**Key Insight:** The quic-go interop test is now correctly processing packet numbers and ACK frames. The remaining blocker is a TLS layer error that prevents the server from sending its handshake response, even though the initial handshake processing (ClientHello parsing, key derivation) succeeds.

### Phase 39 Update: Detailed Error Trace

**New Finding: Error occurs AFTER successful key installation**

Detailed packet sequence:
```
Packet 0: 1239 bytes ClientHello (partial)
  → Processed successfully, no errors

Packet 1: 257 bytes at offset 1239 (completes ClientHello)
  → ClientHello parsed: type=01, len=1492 ✅
  → Handshake secrets derived and installed ✅
  → installHandshakeKeys() completes successfully ✅
  → ERROR: pushCrypto: processCrypto failed with error: error.UnexpectedAlgorithm ❌
```

**Certificate Information:**
- Signature Algorithm: ecdsa-with-SHA256 (P-256)
- Public Key Algorithm: id-ecPublicKey
- Format: PEM (server.crt), OpenSSH private key (server.key)
- Should be supported by ecdsa_secp256r1_sha256 scheme

**Error Source Analysis:**

The error occurs in `vendor/ztls/src/tls13/context.zig:driveServerHandshakeFlight()` which is called from `afterHandshakeMessage()` after successfully parsing ClientHello. The likely culprit:

1. Line 1821: `selectServerSignatureScheme(ch_view)` - tries to negotiate signature algorithm
2. This function iterates through server's supported schemes and client's requested schemes
3. If no match found: returns `HandshakeError.NoSignatureScheme`
4. If certificate parsing fails: throws `error.UnexpectedAlgorithm`

**Root Cause Hypothesis:**

The server's default configuration may not include `ecdsa_secp256r1_sha256` in the supported signature schemes list, or the private key format (OpenSSH) is causing parsing issues when trying to verify certificate compatibility.

**Proposed Fix:**

Need to investigate two areas:
1. Check `Config.supported_signature_schemes` default list
2. Ensure OpenSSH private key format is correctly parsed
3. Add fallback/error recovery in signature scheme selection

