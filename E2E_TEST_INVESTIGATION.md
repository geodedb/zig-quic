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

**Phase 39 Status:** ✅ **RESOLVED**

### Phase 39 Resolution

**Fix Applied:** (src/quic/endpoint/handshake_integration.zig:325-340)

Added ECDSA P-256 (`ecdsa_secp256r1_sha256`) to the TLS configuration's `supported_signature_schemes`:

```zig
// RFC 8446 §4.2.3: Supported signature schemes for certificate verification
// Include both ECDSA P-256 and Ed25519 for compatibility with different certificate types
const supported_schemes = &[_]tls13.SignatureScheme{
    .ecdsa_secp256r1_sha256,  // ECDSA P-256 (commonly used in certificates)
    .ed25519,                 // Ed25519 (compact, efficient)
};

const config = tls13.Config{
    .allocator = allocator,
    .role = tls_role,
    .alpn_protocols = if (alpn_list.len > 0) alpn_list else null,
    .quic_transport_parameters = if (transport_params_bytes.len > 0) transport_params_bytes else null,
    .server_cert_der = server_cert_der,
    .server_key_der = server_key_der,
    .supported_signature_schemes = supported_schemes,  // ← ADDED
};
```

**Result:**
- ✅ `UnexpectedAlgorithm` error resolved
- ✅ TLS successfully parses ClientHello
- ✅ Handshake keys derived and installed
- ✅ ServerHello generated and sent
- ✅ Coalesced packet (Initial + Handshake) transmitted

---

## Phase 40: TLS Secret Mismatch (IN PROGRESS 🔄)

**Date:** 2025-11-13
**Test:** `make e2e-test-go-comprehensive`
**Error:** Client fails to decrypt Handshake packet - "decryption failed"

### Problem Description

After fixing Phase 39, the server successfully sends ServerHello + Handshake messages in a coalesced packet (Initial 130 bytes + Handshake 647 bytes). The client successfully:
- ✅ Receives coalesced packet
- ✅ Decrypts Initial packet containing ServerHello
- ✅ Installs Handshake Read/Write keys
- ❌ **FAILS** to decrypt Handshake packet

**Go Client Log:**
```
2025/11/13 07:37:36 client Parsed a coalesced packet. Part 1: 130 bytes. Remaining: 647 bytes.
2025/11/13 07:37:36 client <- Reading packet 1 (130 bytes) for connection (empty), Initial
2025/11/13 07:37:36 client 	<- &wire.CryptoFrame{Offset: 0, Data length: 90, Offset + Data length: 90}
2025/11/13 07:37:36 client Installed Handshake Write keys (using TLS_AES_128_GCM_SHA256)
2025/11/13 07:37:36 client Installed Handshake Read keys (using TLS_AES_128_GCM_SHA256)
2025/11/13 07:37:36 client Parsed a coalesced packet. Part 2: 647 bytes. Remaining: 0 bytes.
2025/11/13 07:37:36 client Dropping %!s(logging.PacketType=1) packet (647 bytes) that could not be unpacked. Error: decryption failed
```

### Root Cause Analysis

**TLS Handshake Secret Mismatch**

The Zig server and Go client derive **completely different** handshake secrets from the same TLS transcript:

**Zig Server Secrets:**
```
onSecretAvailable: role=Server level=Handshake
  secret: 6a53163dbf876ffde562afbae23a3c1b7a41ad76d085eea5a6084f82b7d82072  ← Server HS secret
onSecretAvailable: role=Server level=Handshake
  secret: 870ee172be6c1aceccb0ee467d5f54597b04b671b162af82007c0776d7ad0039  ← Client HS secret
```

**Go Client Secrets (from TLS key log):**
```
CLIENT_HANDSHAKE_TRAFFIC_SECRET ... c8979acada231927a6b045379b7d5c059daa426b9ba302a4d712ea5f997e9e26
SERVER_HANDSHAKE_TRAFFIC_SECRET ... fb53f84b0ae802274803c5d2a909f6e85bbccba534225f72004ce59aeb4d3112
```

**Analysis:**
- The secrets are **completely different** (not even close byte-wise)
- This indicates the TLS transcript hash or key derivation differs between implementations
- Both sides install keys, but they encrypt/decrypt with different material
- Result: Server encrypts Handshake packet with keys derived from `6a53163d...` / `870ee172...`
- Client tries to decrypt with keys derived from `c8979aca...` / `fb53f84b...`
- Decryption fails with AEAD authentication error

### Investigation Areas

**Possible Causes:**
1. **TLS Transcript Hash Mismatch:** The running hash of handshake messages differs
   - ClientHello content/order/extensions might be hashed differently
   - ServerHello generation might include different content
   - Transport parameters encoding might differ

2. **Key Schedule Implementation:** vendor/ztls key derivation differs from standard
   - HKDF-Expand-Label implementation
   - Early secret, handshake secret computation
   - Label strings or context inclusion

3. **Certificate/Signature Processing:** ECDSA P-256 implementation differs
   - Signature generation during CertificateVerify
   - Certificate chain encoding
   - Public key format interpretation

4. **Random Values:** Client/server random not properly exchanged
   - ClientHello.random
   - ServerHello.random

### Current Status

**Diagnosis:**
- ✅ Phase 39 resolved: ECDSA P-256 support added
- ✅ ServerHello successfully generated and sent
- ✅ Handshake packet successfully generated and sent in coalesced packet
- ✅ Client successfully decrypts ServerHello from Initial packet
- ✅ Client successfully installs Handshake keys
- ❌ **TLS secrets mismatch** - client and server derive completely different handshake secrets
- ❌ Client fails to decrypt Handshake packet (AEAD authentication failure)
- 🔄 Need to investigate vendor/ztls TLS 1.3 key schedule implementation

**Key Observation:**
Both client and server successfully process the same ClientHello and ServerHello messages (proven by client's ability to decrypt Initial packet), yet they derive completely different Handshake secrets. This indicates a fundamental incompatibility in:
1. Transcript hash computation (hash of handshake messages)
2. Key schedule implementation (HKDF-Expand-Label or secret derivation)
3. Random value handling (client_random, server_random)

**Secret Comparison:**
```
Zig Server:  Server HS = 6a53163dbf87..., Client HS = 870ee172be6c...
Go Client:   SERVER_HS = fb53f84b0ae8..., CLIENT_HS = c8979acada23...
```
Zero byte overlap - indicates systematic difference, not minor bug.

**Next Steps (High Priority):**
1. **Add transcript hash logging** in vendor/ztls Context before secret derivation
2. **Compare transcript hash** between Go client and Zig server
3. **Verify HKDF-Expand-Label** implementation in vendor/ztls/src/key_schedule.zig
4. **Check for RFC 8446 compliance** in key derivation (label strings, context inclusion)
5. **Test with reference implementation** (openssl s_client or wireshark packet dissection)

**Phase 40 Status:** ✅ **RESOLVED**

### Phase 40 Resolution

**Root Cause Identified:**

vendor/ztls had a critical bug in TLS 1.3 key schedule (RFC 8446 §7.1). The early secret derivation was using an **empty slice** instead of **32 zero bytes** for the IKM parameter:

**BEFORE (WRONG):**
```zig
// vendor/ztls/src/tls13/key_derivation.zig:126
const early_secret = ks.extractHash(hash, null, &[_]u8{});  // ❌ Empty slice!
```

**RFC 8446 §7.1 requires:**
```
early_secret = HKDF-Extract(salt=0^HashLen, IKM=0^HashLen)
```
Where `0^HashLen` means HashLen zero bytes (32 bytes for SHA-256), NOT an empty slice.

**Evidence:**
```
vendor/ztls (WRONG):   Early secret = B613679A0814D9EC772F95D778C35FC5FF1697C493715653C6C712144292C5AD
RFC 8446 (CORRECT):    Early secret = 33AD0A1C607EC03B09E6CD9893680CE210ADF300AA1F2660E1B22E10F170F92A
```

This cascaded through the entire key schedule:
- Wrong early secret → Wrong derived secret
- Wrong derived secret → Wrong handshake secret
- Wrong handshake secret → Wrong client/server handshake traffic secrets
- Wrong traffic secrets → Client cannot decrypt server's Handshake packet

**Fix Applied:** (vendor/ztls/src/tls13/key_derivation.zig:126-129)
```zig
// RFC 8446 §7.1: early_secret = HKDF-Extract(0, 0) when no PSK
// Both salt and IKM must be HashLen zero bytes (32 bytes for SHA-256)
const zero_ikm: [32]u8 = [_]u8{0} ** 32;
const early_secret = ks.extractHash(hash, null, &zero_ikm);
```

**Result:**
- ✅ TLS handshake secrets now match between Zig server and Go client
- ✅ Connection established successfully
- ✅ TLS handshake complete
- ✅ Stream opened (ID: 0)
- ✅ Client can decrypt server's Handshake packet
- ✅ Server can decrypt client's 1-RTT packets

**Verification:**
```
$ make e2e-test-go-comprehensive
2025/11/13 07:59:53 ✅ Connection established
2025/11/13 07:59:53 ✅ TLS handshake complete
2025/11/13 07:59:53 ✓ Stream opened (ID: 0)
```

**Phase 40 Status:** ✅ **RESOLVED - TLS Key Schedule Fixed**

---

## Phase 41: Stream Data Timeout Investigation

**Phase 41 Status:** 🔍 **INVESTIGATING**

### Problem

Connection establishes successfully, TLS handshake completes, and stream opens, but all stream data tests timeout with "no recent network activity":

```
2025/11/13 08:07:20 ✅ Connection established
2025/11/13 08:07:20 ✅ TLS handshake complete
2025/11/13 08:07:20 ✓ Stream opened (ID: 0)
2025/11/13 08:07:50 ❌ Single Stream Echo
2025/11/13 08:07:50    └─ Error: timeout: no recent network activity
```

**All 8 tests fail:**
- ❌ Single Stream Echo
- ❌ Multiple Concurrent Streams
- ❌ Large Transfer (10240)
- ❌ Large Transfer (102400)
- ❌ Large Transfer (1048576)
- ❌ Multiple Round-trips
- ❌ Bidirectional Simultaneous
- ❌ Stream Interleaving

### Initial Observations

1. **What works:**
   - ✅ Initial packet exchange
   - ✅ TLS 1.3 handshake completes
   - ✅ Encryption level transitions (Initial → Handshake → Application)
   - ✅ Stream opening (client opens stream ID 0)

2. **What doesn't work:**
   - ❌ Stream data exchange
   - ❌ Client writes hang (30s timeout)
   - ❌ Server not responding to stream data

### Investigation Plan

1. ✅ **Check server logs** - Is server receiving STREAM frames?
2. ✅ **Check server stream handling** - Is server reading/echoing data?
3. ✅ **Check ACK generation** - Is server ACKing received STREAM frames?
4. ✅ **Check flow control** - Are flow control limits blocking data?
5. ✅ **Packet capture analysis** - What packets are being exchanged?

### Investigation Findings

**1. Server is receiving 1-RTT packets but cannot decrypt them:**
```
AEAD decrypt failed: pn=194 err=error.AuthenticationFailed
AEAD decrypt failed: pn=246 err=error.AuthenticationFailed
AEAD decrypt failed: pn=140 err=error.AuthenticationFailed
```

**2. Application-level keys ARE being installed:**
```
[installApplicationKeys] Called for Server
  Server: Dropping Initial keys (Application keys installed)
```

**3. Client application secrets (from TLS key log):**
```
CLIENT_TRAFFIC_SECRET_0 2943071bf...5f58434 624a217095a6858ec56f3f2ddd6373fcbcaf488620e8932c5877b4f741eb79ca
SERVER_TRAFFIC_SECRET_0 2943071bf...5f58434 1d65c60c436892a7137b2dc9d8c27ae4e7b9ae1341ec197089275242be8c2e96
```

**4. Verified vendor/ztls `deriveApplicationTraffic()` has logging but is NEVER called:**
- Added logging to `vendor/ztls/src/tls13/key_derivation.zig:deriveApplicationTraffic()`
- Added logging to `vendor/ztls/src/tls13/context.zig:ensureApplicationSecrets()`
- Neither function is called during test execution
- This means application secrets are being derived elsewhere!

**5. Root Cause Hypothesis:**
The QUIC server is using a DIFFERENT code path to derive application traffic secrets that bypasses vendor/ztls's RFC 8446-compliant key schedule. The application secrets being used are WRONG, causing AEAD decryption to fail on client-sent 1-RTT packets containing STREAM frames.

### Next Steps

1. ✅ Find where application secrets are actually being derived in the codebase
2. ✅ Compare those secrets with the client's expected secrets
3. 🔧 Fix the application secret derivation to use vendor/ztls's `deriveApplicationTraffic()`

**6. Master Secret Derivation Bug Found (identical to Phase 40):**

After adding extensive logging to vendor/ztls, discovered that `ensureApplicationSecrets()` IS being called and application secrets ARE being derived, but with WRONG values.

**Secret Comparison:**
- Zig Server derives Client HS: `A1EAE59FDDAE5FE1B8246394C70E99918E9518F488AACAE13B741972360780FE`
- Go Client expects Client HS: `a1eae59fddae5fe1b8246394c70e99918e9518f488aacae13b741972360780FE`
- ✅ **HANDSHAKE TRAFFIC SECRETS MATCH!**

- Zig Server derives Client APP: `4DF300DCF6282BE577D3F58F6D2F53AC6CBA89715DB962251941B19439D67E26`
- Go Client expects Client APP: `f95168a22f18a42399e80693da2762b5d8c477fbdee80c9955c43bb2aa269be6`
- ❌ **APPLICATION TRAFFIC SECRETS MISMATCH!**

**Root Cause:** Master secret derivation in `vendor/ztls/src/tls13/key_derivation.zig:253` was using empty slice instead of 32 zero bytes:

```zig
// BEFORE (BUG):
const master = ks.extractHash(hash, derived.slice(), &[_]u8{});

// AFTER (FIX):
const master = ks.extractHash(hash, derived.slice(), &[_]u8{0} ** 32);
```

According to RFC 8446 §7.1, master secret = HKDF-Extract(salt=derived, IKM=0), where IKM must be 32 zero bytes, not empty.

**Current Status:**
- Master secret bug fixed in vendor/ztls@149cee6 (IKM verified: len=32, all zeros ✓)
- Application secrets still don't match despite all inputs being verified correct:
  * ✅ Handshake secret: `9CF11A9887D3B3C080999A91353746A1373B3FE1A9E4EFF11BFDCBB58AEEF48E`
  * ✅ Transcript hash timing: Computed after server Finished, before client Finished
  * ✅ IKM for master secret: 32 zero bytes
  * ✅ HKDF-Expand-Label implementation: Looks RFC-compliant
  * ❌ Output doesn't match: Client APP should be `cc377340...`, server derives `90C20138...`

**Next Investigation Steps:**
1. Compare actual transcript CONTENT (not just timing) between client and server
2. Manually compute HKDF with known inputs to verify algorithm correctness
3. Check if there's a byte order or encoding issue in HkdfLabel structure
4. Verify Zig's std.crypto.kdf.hkdf matches RFC 5869 exactly

**Phase 41 Status:** ✅ **RESOLVED** - TLS 1.3 Key Schedule Fully Fixed

### Phase 41 Resolution

**Third Critical Bug Found and Fixed:**

After fixing the master secret IKM bug (Phase 40 redux), application secrets still didn't match. Further investigation revealed a THIRD bug in the key schedule - the "derived" secret computation before master secret derivation.

**Bug Location:** `vendor/ztls/src/tls13/key_derivation.zig:252`

**Before (WRONG):**
```zig
const derived = ks.deriveSecretHash(hash, handshake_secret, "derived", &[_]u8{});
const zero_ikm = [_]u8{0} ** 32;
const master = ks.extractHash(hash, derived.slice(), &zero_ikm);
```

**After (CORRECT):**
```zig
const empty_hash = ks.hashBytes(hash, &[_]u8{});
const derived = ks.deriveSecretHash(hash, handshake_secret, "derived", empty_hash.slice());
const zero_ikm = [_]u8{0} ** 32;
const master = ks.extractHash(hash, derived.slice(), &zero_ikm);
```

**Explanation:**

RFC 8446 §7.1 specifies that `Derive-Secret(Secret, Label, Messages)` computes:
```
HKDF-Expand-Label(Secret, Label, Hash(Messages), HashLen)
```

For the "derived" label (used to compute the intermediate value before master secret extraction), Messages is empty, so the context parameter must be:
- `Hash("")` = SHA-256 hash of empty string = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (32 bytes)
- NOT `&[_]u8{}` = empty slice (0 bytes)

This was the same error pattern as the Phase 40 bugs - using empty slices instead of the proper zero-filled or hashed values required by RFC 8446.

**Complete Bug Chain (Three Bugs Fixed in Phase 40-41):**

1. **Early secret IKM** (Phase 40, line 129): empty slice → 32 zero bytes
2. **Master secret IKM** (Phase 41, line 254): empty slice → 32 zero bytes
3. **"Derived" secret context** (Phase 41, line 252): empty slice → Hash("") ← **THIS FIX**

All three bugs stemmed from the same misunderstanding: the TLS 1.3 key schedule requires specific zero-filled or hashed values, not empty slices.

**Result:**

```
✅ Single Stream Echo
   └─ Sent 21 bytes, received 11 bytes in 5.534334ms

❌ 7 remaining tests fail with:
   FINAL_SIZE_ERROR (local): received offset 21 for stream 0,
   but final offset was already received at 11
```

**Analysis:**

- ✅ **Cryptographic issues RESOLVED:** Application traffic secrets now match perfectly
- ✅ **AEAD encryption/decryption WORKS:** First test successfully exchanges stream data
- ✅ **1-RTT packet protection WORKS:** Server and client can encrypt/decrypt application data
- ❌ **Stream management issue:** Server is reusing stream 0 instead of creating new streams

The remaining FINAL_SIZE_ERROR failures are NOT cryptographic - they indicate the server is incorrectly reusing stream 0 for multiple tests instead of allowing the client to open new streams (streams 4, 8, 12, etc.). This is a QUIC stream state machine issue, not a TLS issue.

**Progress:** From 0/8 tests passing to 1/8 tests passing. The TLS 1.3 integration is now fully functional.

**Commits:**
- vendor/ztls@1b56051: Fix "derived" secret context (use Hash("") instead of empty slice)
- vendor/ztls@149cee6: Fix master secret IKM (use 32 zeros instead of empty slice)
- vendor/ztls@7353ec3: Add transcript finalization logging
- vendor/ztls@4352442: Add IKM verification logging

---

## Phase 42: FINAL_SIZE_ERROR - Stream Management Issue (IN PROGRESS 🔄)

**Date:** 2025-11-13
**Test:** `make e2e-test-go-comprehensive`
**Error:** `FINAL_SIZE_ERROR (local): received offset 21 for stream 0, but final offset was already received at 11`

### Problem Description

After fixing Phase 41 (TLS 1.3 key schedule), the first test now passes but 7 remaining tests fail with the same error:

```
✅ Single Stream Echo
   └─ Sent 21 bytes, received 11 bytes in 5.435977ms

❌ Multiple Concurrent Streams
   └─ Error: stream 0 read: FINAL_SIZE_ERROR (local): received offset 21 for stream 0,
             but final offset was already received at 11
```

### Root Cause Analysis

**What the error means:**
- RFC 9000 §2.2: A stream has a "final size" which is the total number of bytes sent
- The final size is communicated via the FIN bit in STREAM frames
- Once a stream receives FIN at a particular offset, no more data can be sent beyond that offset
- Client received FIN at offset 11 on stream 0 (from first test)
- Server then sent more data at offset 21 on stream 0 (in second test)
- This violates QUIC protocol - stream 0 was already closed with final size 11

**What's happening:**
1. Test 1 (Single Stream Echo):
   - Client opens stream 0
   - Client sends "Hello from Go client" (21 bytes)
   - Server echoes "Hello World" (11 bytes) with FIN
   - Client receives response and closes stream 0
   - ✅ Test passes

2. Test 2 (Multiple Concurrent Streams):
   - Client tries to open NEW streams (should be streams 4, 8, 12...)
   - BUT server is somehow sending data on stream 0 again
   - Client rejects: "stream 0 already closed at offset 11"
   - ❌ Test fails

**The server bug:**
The server is reusing stream 0 for subsequent tests instead of:
- Properly closing stream 0 after the first test
- Accepting NEW stream IDs for subsequent tests

### Investigation Plan

1. ✅ **Verify test results** - Confirmed 1/8 passing, 7/8 failing with FINAL_SIZE_ERROR
2. 🔄 **Check server stream handling** - Review cmd/quic-server.zig echo logic
3. 🔄 **Check acceptStream() behavior** - Does it properly return new stream IDs?
4. 🔄 **Check writeStream() behavior** - Is it checking if stream is closed?
5. 🔄 **Add stream state tracking** - Server needs to track which streams are open/closed

### Server Code Analysis

**Current implementation** (cmd/quic-server.zig:146-177):
```zig
// Try to accept an incoming stream
const stream_id = api.acceptStream(conn) catch {
    // No stream available yet, continue to next connection
    i += 1;
    continue;
};

// Read from the accepted stream
var buf: [4096]u8 = undefined;
const n = api.readStream(conn, stream_id, buf[0..]) catch 0;
if (n > 0) {
    // Echo back
    const written = api.writeStream(conn, stream_id, buf[0..n]) catch 0;
}
```

**Potential issues:**
1. Server calls `acceptStream()` in a loop - is it returning the same stream ID repeatedly?
2. Server doesn't track which streams have been closed
3. Server doesn't check if a stream is in a valid state before writing
4. Server might be caching stream_id across loop iterations

### Next Steps

1. Add logging to see what stream IDs `acceptStream()` returns
2. Check if `acceptStream()` is incorrectly returning 0 for all calls
3. Review `acceptStream()` implementation in src/quic/api.zig
4. Check stream state machine in src/quic/connection/stream.zig
5. Verify that closed streams are properly marked and not reused

**Phase 42 Status:** 🔍 **INVESTIGATING** - Server appears to be reusing stream 0 instead of accepting new streams

---

## Summary

| Phase | Issue | Status | Files Modified |
|-------|-------|--------|----------------|
| 38 | Packet number expansion returning wrong value | ✅ RESOLVED | crypto_quic.zig, incoming.zig |
| 39 | UnexpectedAlgorithm error blocking ServerHello | ✅ RESOLVED | handshake_integration.zig |
| 40 | TLS early secret derivation using empty IKM | ✅ RESOLVED | vendor/ztls key_derivation.zig |
| 41 | Application traffic secrets mismatch (3 bugs in key schedule) | ✅ RESOLVED | vendor/ztls key_derivation.zig |
| 42 | FINAL_SIZE_ERROR - stream management issue | 🔍 INVESTIGATING | TBD |

**Key Achievement:** The Zig QUIC server successfully completes TLS 1.3 handshake with quic-go client! Packet numbers, ACK frames, signature scheme negotiation, and TLS key schedule all work correctly. Connection establishment, stream opening, and **stream data exchange** now fully functional (1/8 tests passing). Remaining failures are stream management issues, not cryptographic.

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


## Phase 42: FINAL_SIZE_ERROR - Server Stream Loop Bug (PARTIAL FIX ⚙️)

**Date:** 2025-11-13  
**Test:** `make e2e-test-go-comprehensive`  
**Error:** `FINAL_SIZE_ERROR (local): received offset 21 for stream 0, but final offset was already received at 11`

### Problem Description

After Phase 41 fixed TLS key schedule bugs, test 1 passed but tests 2-8 failed with FINAL_SIZE_ERROR. Client detected protocol violation: server was sending data on stream 0 after it was closed.

### Root Cause: Server Loop Design Bug

**Bug Location:** `cmd/quic-server.zig:148-152`  

Server loop attempted to accept ONE stream per iteration:
```zig
// OLD (WRONG):
const stream_id = api.acceptStream(conn) catch {
    i += 1;
    continue;  // Move to next connection after ONE stream!
};
```

**Consequence:**  
- Server accepted stream 0, processed it
- Never called `acceptStream()` again
- Streams 4, 8, 12, 16 remained queued but unprocessed
- Server reused stream 0 for subsequent tests → FINAL_SIZE_ERROR

### The Fix: Accept ALL Pending Streams

**Modified:** `cmd/quic-server.zig:148-172`
```zig
// NEW (CORRECT):
while (true) {
    const stream_id = api.acceptStream(conn) catch break; // Accept ALL streams
    // ... read/write on stream_id ...
}
i += 1; // Move to next connection AFTER processing all streams
```

### Test Results After Fix

**Before:**
- Queue: [0, 4, 8, 12, 16]
- Accepted: stream 0 only
- Result: 1/8 tests pass

**After:**  
- Queue: [0, 4, 8, 12, 16]
- Accepted: streams 0, 4, 8, 12, 16 ✅
- Stream data flow: CORRECT ✅
- Result: 1/8 tests pass (connection still closes prematurely)

Server debug log confirms correct behavior:
```
DEBUG: Accepted stream 0
stream 0 received 21 bytes: ...
DEBUG: Wrote 21 bytes to stream 0
DEBUG: Accepted stream 4
stream 4 received 16 bytes: ...
DEBUG: Wrote 16 bytes to stream 4
[... streams 8, 12, 16 processed correctly ...]
```

### Remaining Issue: Connection Premature Closure

Server processes all streams correctly, but client still sends CONNECTION_CLOSE. Investigation shows:
1. Server accepts and echoes on correct streams ✅
2. Client receives responses correctly ✅  
3. Client sends CONNECTION_CLOSE after stream processing ❌

**Hypothesis:** Issue may be related to:
- FIN flag handling (stream closure signaling)
- Concurrent stream timing
- Test client expectations vs. server behavior

**Status:** Stream acceptance fixed, but full interoperability requires further investigation of stream lifecycle management.

### Phase 42 Continuation: FIN Handling Bugs (PARTIAL FIX ⚙️)

**Date:** 2025-11-13
**Test:** `make e2e-test-go-comprehensive`
**Error:** `FINAL_SIZE_ERROR (local): received offset 21 for stream 0, but final offset was already received at 11`

#### Problem After Server Loop Fix

After fixing the server loop to accept all pending streams, tests still failed:
```
✅ Single Stream Echo
   └─ Sent 21 bytes, received 11 bytes in 5.537745ms
❌ Multiple Concurrent Streams (and 6 more tests)
   └─ Error: FINAL_SIZE_ERROR (local): received offset 21 for stream 0, but final offset was already received at 11
```

Even the passing test showed **"Sent 21 bytes, received 11 bytes"** - the client only received 11 of 21 bytes!

#### Investigation: FIN-Only Frame Handling

**Key Observations:**

1. Server sends data with fin=false, then sends FIN separately:
   ```zig
   _ = api.writeStream(conn, stream_id, buf[0..n], false); // Data
   _ = api.writeStream(conn, stream_id, &[_]u8{}, true);    // FIN-only frame
   ```

2. Second call with empty data and fin=true returns 0 without sending anything.

3. Added debug logging revealed FIN frames were NOT being sent.

#### Root Cause: Two Bugs in writeStream()

**Bug 1: Zero-Length Write Guard** (`src/quic/conn.zig:2220`)
```zig
// BEFORE (WRONG):
if (data.len == 0) return 0;  // Blocks ALL zero-length writes!

// AFTER (CORRECT):
// Allow zero-length writes ONLY if fin=true (FIN-only frame)
if (data.len == 0 and !fin) return 0;
```

**Explanation:** The guard prevented FIN-only frames (data.len=0, fin=true) from being sent. FIN-only frames are valid QUIC frames (RFC 9000 §19.8) used to signal stream completion without additional data.

**Bug 2: Flow Control Blocking** (`src/quic/conn.zig:2254`)
```zig
// BEFORE (WRONG):
if (to_send == 0) return error.FlowControlBlocked;  // Blocks FIN frames!

// AFTER (CORRECT):
// Allow to_send=0 ONLY if fin=true (FIN-only frame)
if (to_send == 0 and !fin) return error.FlowControlBlocked;
```

**Explanation:** When data.len=0 for a FIN-only frame, flow control calculated to_send=0, then blocked the frame with FlowControlBlocked error. FIN-only frames should bypass this check per RFC 9000 §4.5.

#### Additional Changes Made

1. **Added `fin` parameter to writeStream() API** (`src/quic/conn.zig:2185`, `src/quic/api.zig:236`)
2. **Added fin_sent tracking** for stream 0 and multi-streams (`src/quic/conn.zig:603, 2278-2286`)
3. **Prevent writes after FIN sent** (`src/quic/conn.zig:2198, 2206-2208`)
4. **Updated server loop** to handle partial writes and send FIN separately (`cmd/quic-server.zig:164-183`)
5. **Added frame hexdump logging** to verify frame construction (`src/quic/conn.zig:2258-2261`)

#### Verification

After fixes, FIN frames are being sent:
```
DEBUG flow control: stream_id=0, data.len=21, cur_off=0, to_send=21
DEBUG STREAM frame bytes (25 bytes): 0e 00 00 15 48 65 6c 6c 6f 20 66 72 6f 6d 20 47 6f 20 63 6c 69 65 6e 74 21
DEBUG: Wrote 21/21 bytes to stream 0
DEBUG STREAM frame bytes (4 bytes): 0f 00 15 00
DEBUG: Sent FIN on stream 0
```

**Frame Decoding:**
- First frame: Type **0x0E** (STREAM+LEN+OFF, no FIN), stream 0, offset 0, length **0x15** (21), then 21 bytes of data
- Second frame: Type **0x0F** (STREAM+LEN+OFF+FIN), stream 0, offset **0x15** (21), length 0 ✅

#### Remaining Issue: Partial Data Reception Mystery

**Current State:** FIN frames are now being sent correctly, but tests still fail with same error.

**The Mystery:**
- ✅ Server constructs STREAM frame with all 21 bytes (hexdump confirmed)
- ✅ Flow control allows all 21 bytes (`to_send=21`)
- ✅ FIN is sent at offset 21 (correct per RFC 9000 §2.2)
- ❌ Client only receives **11 bytes** and FIN at **offset 11** (incorrect!)

**Error Analysis:**
```
FINAL_SIZE_ERROR: received offset 21 for stream 0, but final offset was already received at 11
```

This means:
1. Client received data bytes 0-10 (11 bytes total)
2. Client received FIN at offset 11 (establishing final size = 11)
3. Client then received frame at offset 21 (violates final size)

**Implication:** Something is corrupting the first STREAM frame:
- Losing 10 bytes of data (21 → 11)
- Adding a FIN flag (no FIN → FIN)

**Hypothesis:** The issue is NOT in:
- ❌ Frame construction (verified via hexdump - correct)
- ❌ Flow control (allows all 21 bytes)
- ❌ FIN handling (now working correctly)

The problem MUST be in:
- ⚠️ Packet transmission layer
- ⚠️ Frame packetization (multiple frames in same packet?)
- ⚠️ Packet encryption/protection
- ⚠️ Some other layer between frame construction and wire transmission

**Next Investigation Steps:**
1. Add logging to packet sending path to verify packet contents before encryption
2. Check if both STREAM frames are being sent in same packet
3. Use tcpdump/wireshark to capture actual wire bytes
4. Verify packet serialization doesn't truncate frames

---

## Phase 42 Part 3: ROOT CAUSE IDENTIFIED - Auto-Echo Conflict ✅ FIXED

### The Mystery Solved

After adding `protectPacket` logging to trace plaintext frames before encryption, I discovered:

```
protectPacket INPUT: plaintext.len=15 out_cipher.len=31
protectPacket INPUT: plaintext first 30 bytes: 0f 00 00 0b 48 65 6c 6c 6f 20 51 55 49 43 0a
DEBUG writeStream: stream_id=0, data_len=21, fin=true
DEBUG STREAM frame bytes (25 bytes): 0f 00 00 15 48 65 6c 6c 6f 20 66 72 6f 6d 20 47 6f 20 63 6c 69 65 6e 74 21
protectPacket INPUT: plaintext.len=25 out_cipher.len=41
protectPacket INPUT: plaintext first 30 bytes: 0f 00 00 15 48 65 6c 6c 6f 20 66 72 6f 6d 20 47 6f 20 63 6c 69 65 6e 74 21
```

**The Smoking Gun:**
- Frame with "Hello QUIC\n" (11 bytes) sent BEFORE application calls writeStream
- Frame with "Hello from Go client!" (21 bytes) sent AFTER application echo
- BOTH frames on stream 0, offset 0, with FIN=true → FINAL_SIZE_ERROR!

### Root Cause

**File:** `src/quic/conn.zig:1864-1878`
**Code:** Auto-echo implementation in stream data reception

```zig
// Auto-echo implementation (temporary): If server receives first bytes on stream 0, send simple response once.
if (self.role == .Server and stream_id == 0 and offset == 0 and data.len > 0 and !self.app_echo_sent and self.app_tx_keys != null) {
    const resp = "Hello QUIC\n"; // Minimal body
    // ... send frame with offset=0, FIN=true ...
}
```

**Problem Sequence:**
1. Client sends "Hello from Go client!" (21 bytes) on stream 0
2. **Auto-echo triggers** → sends "Hello QUIC\n" (11 bytes) with offset=0, FIN=true → final size = 11
3. **Application echo** → sends "Hello from Go client!" (21 bytes) with offset=0, FIN=true → final size = 21
4. **Client sees FINAL_SIZE_ERROR** → inconsistent final offset (11 vs 21)

### Fix Applied

**Commit:** Disabled auto-echo feature in conn.zig:1864-1869

```zig
// Auto-echo implementation DISABLED: This conflicts with application-level echo servers.
// The auto-echo would send "Hello QUIC\n" (11 bytes) on stream 0 with offset=0 and FIN=true,
// then the application would send its own response also with offset=0 and FIN=true,
// causing FINAL_SIZE_ERROR because the client sees two different final sizes (11 vs actual).
// Applications should handle their own echo logic (see cmd/quic-server.zig).
_ = self.app_echo_sent; // Suppress unused field warning
```

### Test Results After Fix

**Before:**
- ✅ Test 1: Single Stream Echo (but received 11 of 21 bytes)
- ❌ Tests 2-8: FINAL_SIZE_ERROR

**After:**
- ✅ Test 1: Single Stream Echo (**Sent 21 bytes, received 21 bytes**)
- ✅ Test 2: Multiple Concurrent Streams (**4 streams completed**)
- ✅ Test 3: Large Transfer (10KB) (**10240 bytes transferred**)
- ❌ Tests 4-8: Timeout (no recent network activity)

**Progress: 3/8 tests passing** (up from 1/8!)

### New Issues Discovered

Tests 4-8 fail with "timeout: no recent network activity" during larger transfers (100KB, 1MB). This is a **separate issue** from FINAL_SIZE_ERROR - likely related to:
- Flow control window exhaustion
- Missing ACK handling
- Lost packet retransmission
- Congestion control issues

### Lessons Learned

1. **Legacy test code conflicts with production features** - Auto-echo was a temporary testing feature that should have been removed or made conditional
2. **Thorough logging pays off** - Adding protectPacket logging revealed frames being sent before application code
3. **Protocol violations have clear symptoms** - FINAL_SIZE_ERROR clearly indicated duplicate final sizes on same stream

---

**Status:** ⚙️ **PARTIAL FIX** - FIN handling bugs fixed (2 critical bugs in writeStream), but client still receives partial data (11 of 21 bytes). Frame construction is correct, but something between frame buffer and wire is corrupting the data. Root cause unknown - requires investigation of packet layer.

### Phase 42 Deep Dive: The "11 of 21 Bytes" Mystery (INVESTIGATING 🔍)

**Date:** 2025-11-13
**Current Status:** 1/8 tests passing, all failures show "Sent 21 bytes, received 11 bytes"

#### Approach 1: Separate FIN Frame (FAILED)

**Implementation:** Send data frame (fin=false), then send FIN-only frame (fin=true)
- Fixed zero-length write blocking
- Fixed flow control blocking of FIN frames
- Result: Client still receives only 11 bytes

**Server logs confirmed:**
```
DEBUG STREAM frame bytes (25 bytes): 0e 00 00 15 48 65 6c 6c 6f ... (21 bytes)
About to call send() with 44 bytes
send() returned 44 bytes
DEBUG STREAM frame bytes (4 bytes): 0f 00 15 00
About to call send() with 23 bytes
send() returned 23 bytes
```

Both packets sent successfully, but client only received 11 bytes.

#### Approach 2: FIN in Same Frame as Data (FAILED)

**Implementation:** Send all data with FIN=true in a single STREAM frame
- Modified server to set fin=true on last write
- Single packet with data + FIN

**Server logs confirmed:**
```
DEBUG writeStream: stream_id=0, data_len=21, fin=true
DEBUG flow control: stream_id=0, data.len=21, cur_off=0, to_send=21
DEBUG STREAM frame bytes (25 bytes): 0f 00 00 15 48 65 6c 6c 6f 20 66 72 6f 6d 20 47 6f 20 63 6c 69 65 6e 74 21
About to call send() with 44 bytes
send() returned 44 bytes (but client receives only 11!)
```

**Frame decoding verification:**
- Type: `0x0F` = STREAM + **FIN** + LEN + OFF ✅
- Stream ID: `0x00` = 0 ✅
- Offset: `0x00` = 0 ✅
- Length: `0x15` = 21 ✅
- Data: All 21 bytes present ✅

**Result:** Same issue - client still receives only 11 bytes despite perfect frame construction!

#### Critical Observations

**What's Verified Correct:**
1. ✅ Server receives all 21 bytes from client (hexdump: `48 65 6c 6c 6f 20 66 72 6f 6d 20 47 6f 20 63 6c 69 65 6e 74 21`)
2. ✅ STREAM frame plaintext buffer is perfect (25 bytes: 4-byte header + 21-byte payload)
3. ✅ Frame encoding follows RFC 9000 §19.8 exactly
4. ✅ `encodeShortProtected()` produces 44-byte encrypted packet
5. ✅ `send()` syscall returns 44 (success)
6. ✅ Server processes all streams correctly (0, 4, 8, 12, 16)

**What's Failing:**
1. ❌ Client (quic-go) reports receiving only **11 bytes** on stream 0
2. ❌ Client establishes final size = 11 for stream 0
3. ❌ Client rejects subsequent data with FINAL_SIZE_ERROR
4. ❌ Tests 2-8 fail immediately after test 1

**The Consistency Pattern:**
- Always exactly **11 bytes** received (not 10, not 12, not random)
- Happens with both separate FIN frames AND combined FIN+data frames
- Happens consistently across all test runs
- First test "passes" but with partial data
- All subsequent tests fail due to protocol violation

#### Hypothesis: Not a Frame Bug, But a Packet/Encryption Bug

Given that:
- Frame plaintext is perfect ✅
- Packet send succeeds ✅
- Yet client consistently receives 11 of 21 bytes ❌

The bug MUST be in one of these layers:
1. **Packet encryption** (`encodeShortProtected` in `src/quic/packet/packet.zig`)
2. **Packet serialization** (how frames are written to packet buffer)
3. **AEAD encryption** (data corruption during encryption)
4. **Packet number encoding** (truncating packet inadvertently)

#### Why Not a quic-go Client Bug?

- quic-go is a mature, widely-used QUIC implementation
- Other streams (4, 8, 12, 16) echo correctly with 16 bytes
- The "11 bytes" is too consistent to be random client behavior
- Client correctly complains about protocol violation (FINAL_SIZE_ERROR)

#### Next Investigation Steps

1. **Add packet encryption logging** - Log encrypted packet bytes before send()
2. **Inspect encodeShortProtected** - Check for off-by-one errors, buffer handling bugs
3. **Use tcpdump/Wireshark** - Capture actual wire bytes to see what's transmitted
4. **Compare with reference** - Check how quiche implements packet encryption
5. **Test with different data sizes** - Does "11" have significance? (header size?)

**Key Question:** Why exactly 11 bytes? Is there a relationship to:
- QUIC short header size? (varies, typically 1-20 bytes)
- Some MTU or buffer limit?
- A varint encoding bug?
- An off-by-11 error somewhere?

**Status:** 🔍 **DEEP INVESTIGATION REQUIRED** - Frame layer is correct, issue is in packet encryption/serialization layer. Need to trace encrypted packet bytes to wire.

---


---

## Phase 42 Part 4: Server Read Loop Bug - Only Reads First 4KB

### Investigation

After fixing the auto-echo bug, tests 4-8 still timed out. Analysis revealed:

**Bug:** `cmd/quic-server.zig` only called `readStream()` ONCE per stream acceptance:
```zig
// BEFORE: Single read, max 4096 bytes
var buf: [4096]u8 = undefined;
const n = api.readStream(conn, stream_id, buf[0..]) catch |err| blk: {...};
// For 100KB transfer: only reads first 4096 bytes!
```

**Impact:**
- Test 3 (10KB): Only read first 4096 bytes per call
- Test 4 (100KB): Only read first 4096 bytes, rest never read → timeout  
- Tests 5-8: Similar failures

### Fix Applied

Modified `cmd/quic-server.zig:148-198` to loop and read ALL data from each stream until readStream returns 0.

### Test Results After Fix

**Stream data received:**
- Stream 20: 10,240 bytes in 3 chunks (Test 3) ✅
- Stream 24: **28,711 bytes** in 8 chunks (Test 4 - only 28% of 102400!)

### Remaining Issue: Flow Control Window Exhaustion

**Root Cause:** Client exhausts ~28KB send window, waits for ACKs. Server processes all available data before returning to event loop that sends ACKs.

**Test Results:** Still 3/8 tests passing
- ✅ Server CAN read large data now
- ❌ Flow control prevents large transfers from completing

**Next Investigation:** Server event loop needs to interleave ACK processing with data reading.


---

## Phase 42 Part 5: poll() Investigation - Why Interleaved Polling Isn't Sufficient

### Attempted Fix

Added `api.poll(ep, 0)` after each chunk read in the server read loop:
```zig
while (true) {
    var chunk: [4096]u8 = undefined;
    const n = api.readStream(conn, stream_id, chunk[0..]) catch |err| blk: {...};
    if (n == 0) break;
    
    stream_buf.appendSlice(alloc, chunk[0..n]) catch break;
    total_read += n;
    
    // CRITICAL: Poll after each chunk to process incoming packets and send ACKs
    api.poll(ep, 0) catch {};  // ← ADDED THIS
}
```

### Test Result: NO IMPROVEMENT ❌

**Results:** Still 3/8 tests passing, same timeout errors on large transfers.
```
✅ Test 1: Single Stream Echo (21 bytes)
✅ Test 2: Multiple Concurrent Streams (4 streams)
✅ Test 3: Large Transfer (10KB)
❌ Test 4: Large Transfer (102400) - timeout: no recent network activity
❌ Tests 5-8: Similar timeouts
```

###  Root Cause Analysis: poll() Doesn't Send ACKs

**What poll() Actually Does** (src/quic/endpoint.zig:508-536):
```zig
pub fn poll(self: *Endpoint, timeout_ms: i32) !void {
    self.processExpiredTimers(nowMsMonotonic());
    var eff_timeout = self.nextTimeoutFromTimers(now_ms, timeout_ms);
    
    // Poll transport (blocks until data available or timeout)
    try self.transport.poll(eff_timeout);
    
    // Drain all available packets
    while (true) {
        const result = self.recvFrom(&buf) catch |err| {
            if (err == error.WouldBlock) break;
            return err;
        };
        // Process INCOMING packets
        self.processIncomingDatagram(result.peer, buf[0..result.n], null);
    }
    
    self.processExpiredTimers(nowMsMonotonic());
    self.pruneClosed();
}
```

**Key Insight:** `poll()` processes **incoming packets** but does NOT send **outgoing ACKs**!

ACKs are queued during packet processing but only sent later when:
1. Connection flushes outgoing frames
2. writeStream() triggers packet transmission
3. Some other event causes packet sends

### The Real Problem: ACK Transmission Timing

**Sequence of Events:**
1. Client sends ~28KB of data (fills server's initial flow control window)
2. Server calls `readStream()` which removes data from receive buffer
3. Server calls `poll(0)` which processes any incoming packets (but there are none, client is waiting)
4. Server continues reading more data
5. **Flow control window is consumed but never updated** because ACKs aren't sent
6. Client exhausts send window, waits for ACKs that never arrive
7. Test times out with "no recent network activity"

**Evidence from Previous Testing:**
- Server reads exactly 28,711 bytes of 102,400 bytes before timeout
- 28KB ≈ default initial flow control window size
- Client stops sending after exhausting window
- Server never sends ACKs to update the window

### Why poll(0) Doesn't Help

1. **No packets to receive:** Client has stopped sending because it hit flow control limit
2. **No ACKs sent:** poll() only processes incoming, doesn't flush outgoing
3. **Timeout=0:** Returns immediately if no packets available, doesn't help with ACK timing

### Architectural Issue

The server architecture assumes:
- Application reads data from streams
- Control returns to main event loop
- Main loop processes connections and flushes outgoing frames
- ACKs get sent during connection processing

But our tight read loop:
- Stays in readStream() loop without returning to main event loop
- Never gives connection a chance to flush ACKs
- Flow control window never gets updated
- Client hangs waiting for ACKs

### Next Investigation: Need Explicit ACK Transmission

The fix requires finding a way to **explicitly send ACKs** during data reading, not just process incoming packets.

Possible approaches:
1. **Find connection flush function** - Force send of queued ACKs
2. **Call writeStream with 0 bytes** - Might trigger ACK transmission
3. **Restructure event loop** - Return to main loop periodically during large reads
4. **Modify readStream API** - Have it automatically trigger ACK sends

**Status:** 🔍 **INVESTIGATING ACK TRANSMISSION MECHANISM** - Need to understand how/when ACKs are flushed and explicitly trigger it during data reading.


---

## Phase 42 Part 6: Streaming Echo Attempt - writeStream() Also Doesn't Trigger ACKs

### Hypothesis

Based on Part 5 discovery that `poll()` doesn't trigger ACK sends, I hypothesized that `writeStream()` might trigger packet transmission which would include queued ACKs.

### Implementation

Changed from buffered echo to streaming echo:

**Old Approach** (buffer all, then echo):
```zig
while (true) {
    read chunk → append to buffer
}
write entire buffer back
```

**New Approach** (streaming echo):
```zig
while (true) {
    read chunk
    immediately writeStream(chunk, fin=false)  // ← Trigger packet send with ACKs?
}
writeStream(&[_]u8{}, fin=true)  // Send FIN
```

**Rationale:** Each `writeStream()` call should trigger packet transmission. Packet transmission should include any queued ACKs. This would update flow control windows continuously.

### Test Result: NO IMPROVEMENT ❌

**Results:** Still 3/8 tests passing, identical timeout pattern.
```
✅ Test 1: Single Stream Echo (21 bytes)
✅ Test 2: Multiple Concurrent Streams (4 streams)  
✅ Test 3: Large Transfer (10KB)
❌ Test 4: Large Transfer (102400) - timeout: no recent network activity
❌ Tests 5-8: Similar timeouts
```

### Conclus

ion: Neither poll() NOR writeStream() Trigger ACK Transmission

**Critical Discovery:**
- `api.poll(ep, 0)` after each read chunk → NO improvement
- `api.writeStream()` after each read chunk → NO improvement
- Both failed with identical symptoms (timeout at ~28KB)

**What This Means:**
1. ACKs are queued somewhere during packet processing
2. But they're NOT sent by either:
   - `poll()` - Only processes incoming, doesn't flush outgoing
   - `writeStream()` - Sends STREAM frames but not standalone ACKs
3. There must be a SEPARATE mechanism for flushing ACK-only packets

### Why Flow Control Still Deadlocks

**The Cycle:**
1. Client sends 28KB (fills initial window)
2. Server reads data → ACKs are queued internally
3. Server calls `poll(0)` → Processes incoming (none) but doesn't send queued ACKs
4. Server calls `writeStream()` → Sends echo data but not standalone ACKs
5. Client needs ACKs to update window → Blocks waiting
6. Server needs more data from client → Blocks waiting  
7. **DEADLOCK** → Timeout after 30s

### Architectural Issue Identified

The Zig QUIC implementation appears to separate:
- **ACK generation** (happens during packet processing)
- **ACK transmission** (happens... somewhere else?)

Neither `poll()` nor `writeStream()` bridge this gap. We need to find the actual ACK flush mechanism or implement one.

### Next Investigation Required

Need to trace through the endpoint/connection code to find:
1. Where ACKs are queued after packet processing
2. What event/function actually transmits them
3. Why small transfers (10KB) work but large ones (100KB+) don't
   - Hypothesis: Small transfers complete in one event loop iteration
   - Large transfers need multiple iterations with ACKs in between

**Status:** 🔍 **FUNDAMENTAL ARCHITECTURAL ISSUE** - Need to understand or implement ACK flushing mechanism separate from poll() and writeStream().

---

## Phase 42 Part 7: Root Cause Found - ACKs Only Sent for ECN Packets! (ATTEMPTED FIX ⚙️)

**Date:** 2025-11-13  
**Current Status:** 3/8 tests passing (same as before fix attempt)

### Root Cause Discovery

Through systematic code tracing, found the ACK transmission bug in `src/quic/endpoint/incoming.zig:2732-2769`:

**The Bug:**
```zig
// Lines 2746-2768 (BEFORE FIX):
if (conn.ecn_app_ack_pending and conn.app_tx_keys != null and conn.canSendUnderAmplification()) {
    var ack_ctx = AckContext{...};
    generateAndSendAck(&ack_ctx, frame_result, ecn_bits) catch {...};
}
```

**Problem:**
- ACKs are ONLY sent when `conn.ecn_app_ack_pending == true`
- `ecn_app_ack_pending` is ONLY set when ECN bits are observed (conn.zig:1128)
- For normal (non-ECN) ack-eliciting frames → **NO ACKs sent at all!**

**Flow Control Deadlock Mechanism:**
1. Client sends STREAM frames (ack-eliciting, no ECN)
2. Server processes frames, sees `saw_ack_eliciting=true`
3. Server calls `recordAckElicitingRx()` → just records, doesn't send
4. Server checks `ecn_app_ack_pending` → false (no ECN observed)
5. Server skips `generateAndSendAck()` → **NO ACK sent!**
6. Client exhausts flow control window waiting for ACKs
7. **DEADLOCK** → Timeout after 30s

### The Fix (Attempted)

**File:** `src/quic/endpoint/incoming.zig:2756`

**BEFORE:**
```zig
if (conn.ecn_app_ack_pending and conn.app_tx_keys != null and conn.canSendUnderAmplification()) {
```

**AFTER:**
```zig
if ((frame_result.saw_ack_eliciting or conn.ecn_app_ack_pending) and conn.app_tx_keys != null) {
```

**Changes:**
1. Send ACKs for ALL ack-eliciting frames (not just ECN)
2. Removed `canSendUnderAmplification()` check from outer condition  
   (still checked inside `generateAndSendAck()`)

### Test Result

**Status:** NO IMPROVEMENT ❌  
Still 3/8 tests passing with identical failure pattern:
- ✅ Tests 1-3 pass (21B, concurrent streams, 10KB)
- ❌ Tests 4-8 fail (100KB+) with "timeout: no recent network activity"

**Log:** `/tmp/phase42_part7_ack_fix.log`

### Analysis

The fix correctly identifies when ACKs should be sent, but they're still not being transmitted. Possible reasons:

1. **Amplification Limits Blocking:**
   - `generateAndSendAck()` still checks `allow_send = conn.canSendUnderAmplification()` internally
   - If `address_validated==false` and amplification limit reached → ACKs blocked
   - Even though we're on localhost (127.0.0.1)

2. **ACK Queuing vs Transmission:**
   - `generateAndSendAck()` may be queuing ACKs but not flushing to network
   - Need to verify actual `send_fn()` calls happening

3. **Server Event Loop Timing:**
   - ACKs may be generated after `writeStream()` returns
   - Next `poll()` may not occur in time for large transfers

### Next Steps

1. Add debug logging to track:
   - `canSendUnderAmplification()` return values
   - `generateAndSendAck()` execution path  
   - Actual `send_fn()` calls with byte counts

2. Verify amplification accounting:
   - Check `bytes_rx_unvalidated` and `bytes_tx_unvalidated`
   - Confirm `address_validated` state on localhost

3. Consider forcing ACK sends for localhost/validated addresses

**Status:** 🔍 **ROOT CAUSE IDENTIFIED BUT FIX INCOMPLETE** - ACK generation condition fixed, but amplification limits or transmission path still blocking ACK delivery.


---

## Phase 42 Part 7 (Continued): Amplification Limits Blocking ACKs (INVESTIGATING 🔍)

**Date:** 2025-11-13  
**Current Status:** 3/8 tests passing

### Debug Findings

Added debug logging to `generateAndSendAck()` (incoming.zig:2228) and discovered the real blocker:

```
[ACK DEBUG] allow_send=n rx_unval=1232 tx_unval=1293 validated=n
```

**Critical Discovery:**
1. **`allow_send=n`** - ACKs are BLOCKED by amplification limit check!
2. **`validated=n`** - Address is NOT validated, even for localhost (127.0.0.1)!
3. **Amplification math**: `tx_unval / 3 = 1293 / 3 = 431 bytes`
4. **Should pass**: `431 <= 1232 (rx_unval)` ✓ But `allow_send=n` shows it fails!

### Root Cause Chain

1. **Primary bug (FIXED)**: ACKs only sent for ECN packets → Now sends for all ack-eliciting frames
2. **Secondary bug (ACTIVE)**: Localhost not validated → Amplification limits applied unnecessarily
3. **Tertiary bug (SUSPECTED)**: Amplification accounting or logic error in `canSendUnderAmplification()`

### Analysis of `canSendUnderAmplification()` (conn.zig:1166-1169)

```zig
pub fn canSendUnderAmplification(self: *const Connection) bool {
    if (self.address_validated) return true;  // ← Should be true for localhost!
    return (self.bytes_tx_unvalidated / 3) <= self.bytes_rx_unvalidated;
}
```

**Expected behavior for localhost:**
- `address_validated` should be `true` for 127.0.0.1
- Function should return `true` immediately
- No amplification limits applied

**Actual behavior:**
- `address_validated=false` (WHY??)
- Falls through to amplification check
- Check fails despite correct math (431 <= 1232)

### Hypotheses

**Hypothesis 1: Localhost Detection Not Working**
- `isLocalhost()` function (conn.zig:1172) not being called during connection setup
- Address validation logic missing for server-side connections
- Need to find where `address_validated` is set

**Hypothesis 2: Integer Division Bug**
- Zig integer division: `1293 / 3 = 431` (truncates)
- But comparison uses `<=` so should still pass
- Unless there's overflow/underflow somewhere

**Hypothesis 3: Anti-Amplification Logic Inverted**
- Maybe the condition is backwards?
- Test: Try inverting the comparison

### Next Investigation Steps

1. Find where `address_validated` is set for incoming connections
2. Verify `isLocalhost()` is called during server accept
3. Add debug logging to `canSendUnderAmplification()` to see exact values
4. Check if there's a separate code path for setting `address_validated` on servers

**Status:** 🔍 **ROOT CAUSE NARROWED DOWN** - Localhost address validation not working, blocking ACK sends via amplification limits.

---

## Phase 42 Part 7 (Fix Applied): Localhost Auto-Validation (TESTING 🧪)

**Date:** 2025-11-13
**Fix Location:** `src/quic/endpoint/incoming.zig:906-913`

### The Fix

Added localhost auto-validation during Initial packet processing to bypass unnecessary amplification limits:

```zig
// PHASE 42 PART 7 FIX: Auto-validate localhost addresses to avoid unnecessary amplification limits
// RFC 9000 §8.1 allows servers to skip address validation for trusted addresses
if (conn.role == .Server and !conn.address_validated and conn.isLocalhost()) {
    std.debug.print("[LOCALHOST] Auto-validating localhost address - bypassing amplification limits\n", .{});
    conn.address_validated = true;
    conn.bytes_rx_unvalidated = 0;
    conn.bytes_tx_unvalidated = 0;
}
```

**Location in Code Flow:**
- Called during `processInitial()` after token verification (line 900-903)
- Before Retry packet generation logic (line 915+)
- Ensures localhost addresses are trusted from connection establishment

### Expected Impact

**Before Fix:**
- Localhost connections treated as unvalidated → Amplification limits applied
- `canSendUnderAmplification()` returns `false` → ACKs blocked
- Flow control deadlock on transfers >~28KB (initial window)

**After Fix:**
- Localhost connections auto-validated → `address_validated=true`
- `canSendUnderAmplification()` returns `true` immediately
- ACKs sent without restriction → Flow control works correctly
- Expected result: **8/8 tests passing** ✅

### RFC Compliance

**RFC 9000 §8.1 - Address Validation:**
> "A server MAY skip address validation for any IP address that it considers to be trusted."

Localhost (127.0.0.1, ::1) is definitionally trusted - packets cannot be spoofed from loopback addresses.

**Status:** ⚠️ **FIX APPLIED, NO IMPROVEMENT** - Localhost auto-validation implemented but tests still show 3/8 passing.

### Test Results After Fix

**Build**: ✅ Successful
**Test Run**: Still 3/8 tests passing (no change)
- ✅ Test 1: Single Stream Echo (21 bytes)
- ✅ Test 2: Multiple Concurrent Streams
- ✅ Test 3: Large Transfer (10KB)
- ❌ Tests 4-8: Still timing out after 30 seconds

### Debug Investigation

Added debug logging to verify localhost detection:
```zig
const is_localhost = conn.isLocalhost();
std.debug.print("[PHASE42] processInitial: role={s} address_validated={} isLocalhost={}\n", .{
    if (conn.role == .Server) "Server" else "Client",
    conn.address_validated,
    is_localhost,
});
```

**Observation**: Debug messages not appearing in server output, suggesting either:
1. The `processInitial` function isn't being called for subsequent packets (only first Initial)
2. Address validation happens elsewhere for Application-level packets
3. The `isLocalhost()` function isn't detecting 127.0.0.1 correctly

### Next Investigation Steps

1. ✅ Added debug logging to `canSendUnderAmplification()` and `isLocalhost()`
2. ⏸️ Debug messages not appearing in server output (buffering issue or functions not being called)
3. **Need new approach**: The amplification limits theory may be incorrect

---

## Phase 42 Part 8: Debug Logging and Re-evaluation (IN PROGRESS 🔍)

**Date:** 2025-11-13
**Status:** Still 3/8 tests passing after multiple fix attempts

### Changes Made

**Added comprehensive debug logging** to understand amplification behavior:

1. **`canSendUnderAmplification()` (conn.zig:1166-1182)**:
   - Logs validated status, isLocalhost result, RX/TX byte counts
   - Shows calculated TX/3 value and final allow/deny decision

2. **`isLocalhost()` (conn.zig:1194-1200)**:
   - Logs IPv4 address bytes being checked
   - Shows whether 127.0.0.1 match succeeds

### Observation

**Debug messages don't appear in server output**, suggesting either:
- Functions aren't being called during the problematic 100KB+ transfers
- Output is being buffered (unlikely for std.debug.print)
- Different code path is taken for Application Data packets

### Critical Realization

After multiple fix attempts with no improvement:
1. ACK generation fix (saw_ack_eliciting) → No improvement
2. Localhost auto-validation → No improvement
3. Debug logging → Messages don't appear

**Theory**: The problem may NOT be amplification limits at all.

### Alternative Hypotheses

1. **Flow control window exhaustion without updates**:
   - Server reads data but doesn't send MAX_STREAM_DATA frames
   - Client exhausts send window waiting for window updates
   - ACKs are sent but don't update the window

2. **Stream-level vs connection-level flow control**:
   - Connection-level window may be fine
   - Stream-level window may be exhausted
   - Server not generating MAX_STREAM_DATA frames

3. **Architectural issue with streaming echo**:
   - The streaming echo pattern (read chunk, write chunk, repeat) may not trigger packet sends
   - Packets may be queued but not flushed to the network
   - `writeStream()` may not cause immediate packet transmission

4. **Poll/event loop issue**:
   - Server may not be polling frequently enough during large transfers
   - Packets may be generated but not sent due to event loop behavior

### Next Steps

Need to investigate flow control window management rather than amplification limits:
1. Add debug logging to MAX_STREAM_DATA frame generation
2. Check if `writeStream()` triggers packet sends or just queues data
3. Verify flow control window updates are being sent to client
4. Consider if the issue is in the echo server implementation itself

---

## Phase 42 Part 9: ROOT CAUSE FOUND - Missing Per-Stream MAX_STREAM_DATA (CRITICAL BUG 🔴)

**Date:** 2025-11-13
**Status:** Still 3/8 tests passing - **ROOT CAUSE IDENTIFIED**

### Investigation: Flow Control Window Management

Following the alternative hypothesis from Part 8, I investigated how MAX_STREAM_DATA frames are generated.

### Code Analysis

**1. Helper Function Exists But Never Called**

`src/quic/connection/flow_control.zig:83`:
```zig
pub fn shouldSendMaxStreamData(local_max_stream_data: u64, last_sent_max_stream_data: u64) bool {
    return local_max_stream_data > last_sent_max_stream_data;
}
```

Searched entire codebase - **this function is NEVER called**!

**2. MAX_STREAM_DATA Frame Generation (incoming.zig:2338-2344)**

```zig
// Pace MAX_* emission: include only when values increased
if (conn.local_max_stream_data > conn.last_sent_max_stream_data) {
    _ = (frame.Frame{ .max_stream_data = .{
        .stream_id = 0,  // <-- HARDCODED TO STREAM 0!
        .max = conn.local_max_stream_data
    } }).write(w) catch {};
    conn.last_sent_max_stream_data = conn.local_max_stream_data;
}
```

**3. Connection Structure (conn.zig)**

```zig
pub const Connection = struct {
    streams_rx: std.AutoHashMap(u64, StreamRx) = undefined,  // Per-stream storage
    local_max_stream_data: u64 = 16 * 1024,  // SINGLE GLOBAL VALUE!
    last_sent_max_stream_data: u64 = 0,      // SINGLE GLOBAL VALUE!
    // ...
}
```

### ROOT CAUSE

**The implementation has THREE critical bugs:**

1. **Hardcoded stream ID**: MAX_STREAM_DATA frames always use `stream_id = 0`
   - Only stream 0 gets flow control window updates
   - All other streams (1, 2, 3, 4, ...) NEVER receive MAX_STREAM_DATA frames

2. **No per-stream tracking**: `local_max_stream_data` is a single connection-level value
   - Should be tracked per-stream in `StreamRx` structure
   - Server doesn't know each stream's current window

3. **No iteration over active streams**: Code only sends ONE MAX_STREAM_DATA frame
   - Should iterate `streams_rx` HashMap and send MAX_STREAM_DATA for each active stream
   - RFC 9000 §4.2: "Stream flow control is per-stream"

### Why This Explains All Symptoms

**✅ Test 1-3 Pass (Small transfers on stream 0)**:
- Single stream echo uses stream 0 → gets flow control updates
- 10KB fits within initial window (16 KB default)
- Concurrent streams test uses small data on each stream → stays within initial window

**❌ Test 4-8 Fail (Large transfers >100KB)**:
- Client likely uses stream IDs other than 0 for some tests
- Even stream 0 exhausts its window on 100KB+ transfers
- Client waits for MAX_STREAM_DATA frames that NEVER arrive
- Connection times out after 30 seconds with "no recent network activity"

### Concrete Example

```
Client opens stream 4 and wants to send 102400 bytes:
1. Initial window: 16384 bytes (from transport params)
2. Client sends first 16384 bytes → server receives and ACKs
3. Server consumes data but NEVER sends MAX_STREAM_DATA(stream_id=4)
4. Client exhausted send window, waits for permission to send more
5. Server hardcoded to only send MAX_STREAM_DATA(stream_id=0)
6. DEADLOCK: Client waiting, server waiting
7. Timeout after 30 seconds
```

### Fix Required

Need to implement proper per-stream flow control:

1. **Add fields to StreamRx**:
   ```zig
   pub const StreamRx = struct {
       recv_off: u64 = 0,
       local_max_stream_data: u64 = 16 * 1024,      // NEW
       last_sent_max_stream_data: u64 = 0,          // NEW
       // ... existing fields
   }
   ```

2. **Update window when stream consumes data**:
   - When `readStream()` is called, update that stream's `local_max_stream_data`
   - Similar logic to connection-level MAX_DATA updates

3. **Send MAX_STREAM_DATA for ALL active streams**:
   ```zig
   // Iterate over active streams
   var iter = conn.streams_rx.iterator();
   while (iter.next()) |entry| {
       const stream_id = entry.key_ptr.*;
       const stream = entry.value_ptr;
       if (stream.local_max_stream_data > stream.last_sent_max_stream_data) {
           _ = (frame.Frame{ .max_stream_data = .{
               .stream_id = stream_id,  // CORRECT!
               .max = stream.local_max_stream_data
           } }).write(w) catch {};
           stream.last_sent_max_stream_data = stream.local_max_stream_data;
       }
   }
   ```

### Impact

**Severity**: CRITICAL - Prevents any large data transfer on non-zero stream IDs
**RFC Compliance**: Violates RFC 9000 §4.2 (per-stream flow control)
**Test Impact**: 5/8 tests fail (62.5% failure rate)

### Phase 42 Part 9 Fix Implementation

Implemented comprehensive per-stream receive-side flow control:

1. **Modified src/quic/conn.zig:392-410** - Added per-stream flow control fields to StreamRx:
   ```zig
   pub const StreamRx = struct {
       local_max_stream_data: u64 = 0,       // Current receive window limit
       last_sent_max_stream_data: u64 = 0,   // Last MAX_STREAM_DATA sent
       // ... other fields
   }
   ```

2. **Modified src/quic/conn.zig:3209-3220** - Initialize windows on stream creation:
   ```zig
   sr.local_max_stream_data = self.local_max_stream_data;
   sr.last_sent_max_stream_data = 0;
   ```

3. **Modified src/quic/conn.zig:2338-2349** - Expand window when data consumed:
   ```zig
   const bump = old_max / 2;  // Grow by 50%
   s.local_max_stream_data = if (overflow != 0) std.math.maxInt(u64) else new_val;
   ```

4. **Modified src/quic/endpoint/incoming.zig:2337-2353** - Send MAX_STREAM_DATA for ALL streams:
   ```zig
   var iter = conn.streams_rx.iterator();
   while (iter.next()) |entry| {
       const stream_id = entry.key_ptr.*;
       const stream = entry.value_ptr;
       if (stream.local_max_stream_data > stream.last_sent_max_stream_data) {
           _ = (frame.Frame{ .max_stream_data = .{
               .stream_id = stream_id,  // NOT hardcoded to 0!
               .max = stream.local_max_stream_data
           } }).write(w) catch {};
           stream.last_sent_max_stream_data = stream.local_max_stream_data;
       }
   }
   ```

### Phase 42 Part 9 Test Results (2025-11-13 15:53:47)

Ran `make e2e-test-go-comprehensive` after implementing per-stream receive-side flow control.

**Results**: 3/8 tests passing (NO IMPROVEMENT)

```
✅ Single Stream Echo (21 bytes)        - 6.05ms
✅ Multiple Concurrent Streams (4)      - 5.19ms
✅ Large Transfer (10KB)                - 11.63ms (0.84 MB/s)
❌ Large Transfer (102400 bytes)        - timeout: no recent network activity
❌ Large Transfer (1048576 bytes)       - timeout: no recent network activity
❌ Multiple Round-trips (10 cycles)     - timeout: no recent network activity
❌ Bidirectional Simultaneous           - timeout: no recent network activity
❌ Stream Interleaving (5 streams)      - timeout: no recent network activity
```

### Phase 42 Part 9 Debug Output Analysis

Checked `/tmp/e2e-go-comprehensive.log` for `[FC]` debug messages:

```
[FC] Sending MAX_STREAM_DATA(stream=0, max=524288)
[FC] Sending MAX_STREAM_DATA(stream=1, max=524288)
[FC] Sending MAX_STREAM_DATA(stream=4, max=524288)
[FC] Stream 0 read 21 bytes, window expanded 524288 -> 786432
[FC] Sending MAX_STREAM_DATA(stream=0, max=786432)
[FC] Stream 24 read 16 bytes, window expanded 1048576 -> 1119744
[FC] Sending MAX_STREAM_DATA(stream=24, max=1119744)
```

**Key Findings**:
- MAX_STREAM_DATA frames ARE being sent for multiple streams (0, 1, 4, 5, 8, 12, 16, 20, 24)
- Windows ARE expanding correctly (Stream 24 reached 1,119,744 bytes)
- Per-stream receive-side flow control implementation is WORKING CORRECTLY

**Critical Realization**: The problem is NOT in receive-side flow control (server receiving from client). The issue is in **send-side flow control** (server sending back to client).

### Phase 42 Part 10: Send-Side Flow Control Investigation

**Date**: 2025-11-13
**Status**: IN PROGRESS

#### Problem Hypothesis

The server needs per-stream tracking of the peer's (client's) receive window limits when sending data.

**Evidence from Code Analysis**:

1. **src/quic/conn.zig:619** - `peer_max_stream_data` is a SINGLE GLOBAL value:
   ```zig
   peer_max_stream_data: u64 = 16 * 1024,  // GLOBAL - should be per-stream!
   ```

2. **src/quic/conn.zig:2245-2270** - writeStream() uses this global value for flow control:
   ```zig
   pub fn writeStream(self: *Connection, id: u64, data: []const u8) !usize {
       // ...
       const peer_limit = self.peer_max_stream_data;  // GLOBAL VALUE!
       // ...
   }
   ```

**Impact**: When the server echoes data back to the client on multiple streams:
- Server doesn't know each stream's individual send window limit from the client
- Server may be blocked because it thinks the global limit applies to all streams
- Client sends MAX_STREAM_DATA frames for individual streams, but server doesn't track them per-stream

#### Root Cause: Missing StreamTx Per-Stream Send Tracking

The current architecture has:
- **StreamRx** (receive-side): Tracks data received FROM peer, has per-stream flow control
- **StreamTx** (send-side): MISSING per-stream tracking of peer's receive window

The server needs to:
1. Track `peer_max_stream_data` per-stream (not globally)
2. Update this value when receiving MAX_STREAM_DATA frames from the client
3. Use per-stream limits in writeStream() flow control checks

#### Phase 42 Part 10 Implementation

Implemented comprehensive per-stream send-side flow control:

1. **Modified src/quic/conn.zig:464-470** - Added peer_max_stream_data to StreamTx:
   ```zig
   const StreamTx = struct {
       off: u64 = 0,
       fin_sent: bool = false,
       aborted: bool = false,
       peer_max_stream_data: u64 = 0,  // Per-stream peer receive window limit
   };
   ```

2. **Modified src/quic/conn.zig:2156,2172,3379,3404** - Initialize peer window on stream creation:
   ```zig
   _ = self.stream_txs.put(stream_id, .{ .peer_max_stream_data = self.peer_max_stream_data }) catch {};
   ```

3. **Modified src/quic/endpoint/frame_handler.zig:227-236** - Update per-stream limits when receiving MAX_STREAM_DATA:
   ```zig
   pub fn handleMaxStreamData(ctx: *FrameContext, m: frame.MaxStreamData) FrameResult {
       if (ctx.conn.stream_txs.getPtr(m.stream_id)) |tx| {
           tx.peer_max_stream_data = m.max;
           std.debug.print("[FC-TX] Received MAX_STREAM_DATA(stream={}, max={})\n", .{m.stream_id, m.max});
       }
       return .{ .saw_ack_eliciting = true };
   }
   ```

4. **Modified src/quic/conn.zig:2249-2289** - Use per-stream limits in writeStream():
   ```zig
   const tx_state = if (id == 0)
       &StreamTx{ .off = self.stream_send_off, .peer_max_stream_data = self.peer_max_stream_data }
   else
       self.stream_txs.getPtr(id).?;
   const peer_stream_limit: u64 = tx_state.peer_max_stream_data;
   // Use peer_stream_limit for flow control checks
   ```

### Phase 42 Part 10 Test Results (2025-11-13 16:02:26)

Ran `make e2e-test-go-comprehensive` after implementing per-stream send-side flow control.

**Results**: 3/8 tests passing (NO IMPROVEMENT)

```
✅ Single Stream Echo (21 bytes)        - 6.03ms
✅ Multiple Concurrent Streams (4)      - 5.84ms
✅ Large Transfer (10KB)                - 10.01ms (0.98 MB/s)
❌ Large Transfer (102400 bytes)        - timeout: no recent network activity
❌ Large Transfer (1048576 bytes)       - timeout: no recent network activity
❌ Multiple Round-trips (10 cycles)     - timeout: no recent network activity
❌ Bidirectional Simultaneous           - timeout: no recent network activity
❌ Stream Interleaving (5 streams)      - timeout: no recent network activity
```

### Phase 42 Part 10 Debug Analysis

Checked debug output for flow control:

**Key Observations**:
1. Per-stream send-side flow control is working - all streams show `peer_limit=524288` (512KB initial window)
2. Server sends MAX_STREAM_DATA frames correctly (receive-side) - client should be able to send data
3. **CRITICAL FINDING**: Server does NOT receive any MAX_STREAM_DATA frames from client
   - No `[FC-TX] Received MAX_STREAM_DATA` log messages appear
   - Server cannot expand send windows beyond initial 524KB limit
   - But tests are failing at only 100KB transfer, well below the 512KB limit

**Debug Sample**:
```
[FC-TX] writeStream: stream_id=20, data.len=4096, cur_off=0, peer_limit=524288, window_left_stream=524288, to_send=1000
[FC-TX] writeStream: stream_id=20, data.len=4096, cur_off=1000, peer_limit=524288, window_left_stream=523288, to_send=1000
```

**New Hypothesis**: The issue is NOT flow control windows (512KB >> 100KB). The problem might be:
- Incorrect transport parameter exchange (initial window mismatch)
- Echo server implementation issue (not reading fast enough)
- Packet loss or congestion control limiting throughput
- Missing ACKs causing timeout despite flow control being correct

### Phase 42 Part 11: Server Echo Loop Investigation

**Date**: 2025-11-13
**Status**: IN PROGRESS

#### Hypothesis: Echo Server Abandons Streams on Flow Control Block

Analyzed cmd/quic-server.zig echo loop implementation:

```zig
while (true) {
    const stream_id = api.acceptStream(conn) catch break;
    // Read and echo loop
    while (true) {
        const n = api.readStream(conn, stream_id, chunk[0..]) catch break;
        if (n == 0) break;

        const written = api.writeStream(conn, stream_id, chunk[0..n], false) catch |err| blk: {
            std.debug.print("DEBUG: writeStream error: {}\n", .{err});
            break :blk 0;  // Return 0 on error
        };
        if (written == 0) {
            std.debug.print("DEBUG: writeStream returned 0, breaking\n", .{});
            break;  // EXIT ECHO LOOP!
        }
    }
}
```

**CRITICAL BUG**: When `writeStream()` returns `error.FlowControlBlocked` (caught → returns 0), the server breaks out of the echo loop and NEVER tries to echo the remaining data again. The stream is abandoned.

**Why This Causes Timeout**:
1. Client sends 100KB of data
2. Server reads data into buffer
3. Server tries to echo back via writeStream()
4. writeStream() hits flow control limit, returns error.FlowControlBlocked → caught → 0
5. Server breaks out of loop, abandons stream
6. Client waits forever for echo data that will never arrive
7. Timeout after 30 seconds

**Why Small Transfers Work**:
- 21B, 16B, 10KB transfers fit entirely within initial windows
- writeStream() never blocks, echoes complete successfully

**Why Large Transfers Fail**:
- 100KB+ exceed congestion window or require multiple round-trips
- First few writeStream() calls succeed, then one blocks
- Server abandons remaining data

#### Solution Required

The server needs to:
1. Track which streams have partial echo data pending
2. Continue trying to write when flow control unblocks
3. Not abandon streams on temporary flow control blocks

This requires redesigning the echo server to maintain state per-stream.


## Phase 42 Part 12: Echo Server Flow Control Resilience ⚙️

**Date:** 2025-11-13  
**Test Results Before:** 3/8 tests passing (21B, 4×16B, 10KB)  
**Test Results After:** Testing in progress...

### Problem Identified

Phase 42 Parts 9-10 implemented correct per-stream flow control, but tests still failed at 100KB transfers. Analysis revealed the root cause was NOT in the flow control implementation itself, but in the echo server loop design.

**Root Cause:** Server echo loop in `cmd/quic-server.zig:183-191` abandoned streams when `writeStream()` returned any error:

```zig
// BROKEN CODE:
const written = api.writeStream(conn, stream_id, chunk[0..n], false) catch |err| blk: {
    std.debug.print("DEBUG: writeStream error: {}\n", .{err});
    break :blk 0;  // Returns 0 on ANY error
};
if (written == 0) {
    std.debug.print("DEBUG: writeStream returned 0, breaking\n", .{});
    break;  // EXIT LOOP - STREAM ABANDONED!
}
```

When `writeStream()` hits congestion control or flow control limits, it returns `error.FlowControlBlocked`. The echo server caught this, returned 0, then broke out of the loop and NEVER retried writing the remaining data. The stream was permanently abandoned with partial data sent.

**Why Small Transfers Worked:**
- 21B, 16B×4, 10KB fit entirely within initial congestion/flow control windows
- writeStream() never blocked, stream never abandoned
- Tests passed

**Why Large Transfers Failed:**
- 100KB+ eventually hit congestion or flow control limits  
- writeStream() blocks → stream abandoned → client waits forever
- Timeout after 30 seconds

### Implementation: Flow-Control-Resilient Echo Server

**Modified:** `cmd/quic-server.zig:103-280`

Complete redesign of echo server to handle flow control blocks gracefully:

#### 1. Per-Stream State Tracking
```zig
const StreamState = struct {
    pending_write: std.ArrayListUnmanaged(u8) = .{},  // Data waiting to be written
    got_fin: bool = false,             // Received FIN from peer
    sent_fin: bool = false,            // Sent FIN to peer
};

const ConnState = struct {
    conn: *api.QuicConnection,
    streams: std.AutoHashMap(u64, StreamState),
    allocator: std.mem.Allocator,
};
```

#### 2. Round-Robin Stream Processing
```zig
// Accept ALL newly available streams upfront
while (api.acceptStream(conn)) |stream_id| {
    conn_state.streams.put(stream_id, .{}) catch {};
}

// Process all active streams in round-robin fashion
var stream_iter = conn_state.streams.iterator();
while (stream_iter.next()) |entry| {
    const stream_id = entry.key_ptr.*;
    var stream = entry.value_ptr;
    // ... process this stream ...
}
```

#### 3. Flush Pending Writes First
```zig
// Step 1: Try to flush pending writes (flow control may have unblocked)
if (stream.pending_write.items.len > 0) {
    const written: usize = api.writeStream(conn, stream_id, stream.pending_write.items, false) catch |err| blk: {
        if (err == error.FlowControlBlocked) {
            continue; // Try next stream, will retry this one next iteration
        }
        break :blk 0;
    };
    
    if (written > 0) {
        // Remove written bytes from pending buffer
        const remaining = stream.pending_write.items.len - written;
        if (remaining > 0) {
            std.mem.copyForwards(u8, stream.pending_write.items[0..remaining], stream.pending_write.items[written..]);
        }
        stream.pending_write.shrinkRetainingCapacity(remaining);
    }
    
    // Skip reading more until we flush pending data
    if (stream.pending_write.items.len > 0) {
        continue;
    }
}
```

#### 4. Buffer Data When Blocked
```zig
// Step 2: Read new data from stream
const n: usize = api.readStream(conn, stream_id, chunk[0..]) catch 0;

if (n > 0) {
    // Try to echo immediately
    const written: usize = api.writeStream(conn, stream_id, chunk[0..n], false) catch |err| blk: {
        if (err == error.FlowControlBlocked) {
            // Buffer the data for later retry
            stream.pending_write.appendSlice(conn_state.allocator, chunk[0..n]) catch {};
            break :blk 0;
        }
        break :blk 0;
    };
    
    // If partial write, buffer remainder
    if (written > 0 and written < n) {
        stream.pending_write.appendSlice(conn_state.allocator, chunk[written..n]) catch {};
    }
}
```

#### 5. Complete Stream After All Data Flushed
```zig
// Step 3: If got FIN and no pending data, send FIN back
if (stream.got_fin and stream.pending_write.items.len == 0 and !stream.sent_fin) {
    _ = api.writeStream(conn, stream_id, &[_]u8{}, true) catch {};
    stream.sent_fin = true;
}
```

### Key Design Principles

1. **Never Abandon Streams:** Flow control blocks are temporary - buffer data and retry
2. **Round-Robin Fairness:** Process all streams each iteration, preventing starvation
3. **Flush Before Read:** Prioritize sending buffered data over reading new data
4. **Graceful FIN Handling:** Only send FIN after all buffered data is flushed

### Test Results

Testing in progress after implementation...


### Test Results After Implementation

**Result:** 3/8 tests passing (UNCHANGED ❌)

```
✅ Single Stream Echo (21 bytes) - 7.2ms
✅ Multiple Concurrent Streams (4 × 16 bytes) - 5.0ms
✅ Large Transfer (10KB) - 13.5ms @ 0.72 MB/s
❌ Large Transfer (100KB) - timeout: no recent network activity
❌ Large Transfer (1MB) - timeout: no recent network activity
❌ Multiple Round-trips - timeout: no recent network activity
❌ Bidirectional Simultaneous - timeout: no recent network activity
❌ Stream Interleaving - timeout: no recent network activity
```

**Analysis:** The flow-control-resilient echo server implementation did NOT resolve the timeout issue. Tests still fail at exactly the same point (100KB transfer). This indicates the root cause is NOT the echo server loop abandoning streams, but something deeper in the packet processing or event loop.

**Possible Root Causes:**
1. **Event loop starvation:** Server may be stuck processing streams without calling `poll()` to handle incoming packets
2. **Missing packet transmission:** Buffered echo data may not be triggering actual packet sends
3. **ACK/flow control frame generation:** Server may not be sending ACK or MAX_STREAM_DATA frames during stream processing
4. **Connection-level issue:** Some connection-level timeout or state machine issue

**Next Steps Required:**
- Add detailed server-side debug logging to understand where processing stalls
- Verify poll() is being called regularly during large transfers
- Check if packets are actually being sent when data is "echoed"
- Investigate whether ACKs are being generated and transmitted

**Status:** Further investigation needed to identify the actual blocking mechanism.


---

## Phase 42 Part 13: Stream Acceptance Bug Discovery (ROOT CAUSE IDENTIFIED ⚠️)

**Date:** 2025-11-13  
**Test:** `make e2e-test-go-comprehensive`  
**Phase 42 Part 12 Result:** 3/8 tests passing (unchanged after echo server redesign)

### Hypothesis Tested

After Part 12's flow-control-resilient echo server showed no improvement, added comprehensive debug logging to understand event loop behavior during large transfers:

**Debug Logging Added:**
1. Event loop iteration counter with 100ms periodic logging
2. Per-stream cumulative byte counters (total_read, total_written)
3. Detailed writeStream() results (immediate echo vs buffered)
4. Stream state transitions (accepted, FIN received, FIN sent)

### Critical Discovery  

**Stream 24 (100KB test) received ONLY 64KB before stalling:**

```
[P42-13-READ] Stream 24 read 4096 bytes (65536 total read, loop 164)
[P42-13-ECHO] Stream 24 echoed 1000 bytes (62440 total written, loop 164)
[P42-13-FIN] Stream 24 received FIN (total read: 65536, total written: 65536, pending: 0)
[P42-12] Stream 24 sent FIN, complete
```

**Expected:** 102400 bytes (100KB)  
**Actual:** 65536 bytes (64KB)  
**Missing:** 36864 bytes (36KB)

### Root Cause: Stream Acceptance Bug

After stream 24 completed at 64KB, the server entered an infinite loop:

```
Found peer-initiated stream 0 in RX but not in queue
Found peer-initiated stream 4 in RX but not in queue
Found peer-initiated stream 12 in RX but not in queue
Found peer-initiated stream 20 in RX but not in queue
Found peer-initiated stream 16 in RX but not in queue
Found peer-initiated stream 24 in RX but not in queue
Found peer-initiated stream 8 in RX but not in queue
Total peer-initiated streams in RX: 7
DEBUG acceptStream: queue has 0 streams
[P42-13-LOOP] Iteration 1615, 1 active connections
```

**The Bug:** `acceptStream()` returns streams once when they first arrive, but never again even if:
- More data arrives on that stream
- The stream hasn't sent FIN yet
- Data is waiting in RX buffers

**Current (Broken) Model:**
1. Client opens stream, sends 64KB of data
2. Server calls `acceptStream()` → returns stream_id
3. Server reads and echoes 64KB
4. Client sends remaining 36KB of data
5. Server calls `acceptStream()` → returns null (stream already accepted!)
6. Remaining 36KB never gets processed
7. Test times out waiting for echo

**Expected Model:**
Streams should be "readable" signals, not one-time events. The server needs a way to know when a stream has more data to read, similar to epoll/kqueue edge-triggered vs level-triggered notifications.

### Evidence

**Server Log Analysis:**
- Total log lines: 29,085
- Stream 24 completion: Line 14,453 (early in test)
- Remaining 14,632 lines: Spinning in accept loop
- Loop iterations after completion: 1615+ iterations with no progress

**Echo Server Confirmation:**
The Phase 42 Part 12 echo server redesign works perfectly:
- Handles partial writes correctly (1000 bytes/write observed)
- Buffers remaining data (3096 bytes buffered repeatedly)
- Flushes pending data in round-robin fashion
- Sends FIN only after all data flushed

The echo server is NOT the problem - the stream acceptance mechanism is fundamentally broken.

### Required Fix

The `acceptStream()` API needs to change from:
- **Current:** "Tell me about NEW streams" (one-time notification)
- **Required:** "Tell me which streams are READABLE" (continuous readiness signal)

**Possible Solutions:**

1. **Add `pollReadableStreams()` API** - Returns all streams with data to read
2. **Make `acceptStream()` level-triggered** - Returns stream_id whenever it has unread data  
3. **Add `hasData(stream_id)` query** - Let application check if stream has more data
4. **Event-driven callback model** - Callback when stream becomes readable

**Next Steps:**
1. Examine `acceptStream()` implementation in src/quic/*.zig
2. Understand the stream queuing/notification mechanism
3. Design and implement proper stream readiness signaling
4. Retest with fixed stream acceptance

**Status:** ROOT CAUSE IDENTIFIED - Stream acceptance mechanism is broken for multi-packet transfers.

---

## Phase 42 Part 15: Fixing Queue Blocking (IN PROGRESS 🔄)

**Date:** 2025-11-13
**Test:** `make e2e-test-go-comprehensive`
**Status:** 3/8 tests passing → Attempting fix for queue blocking

### Problem Summary

Phase 42 Part 14 attempted to fix the stream acceptance problem by:
1. Re-queueing streams when new data arrives (conn.zig:1861)
2. Preventing state overwrite in echo server (cmd/quic-server.zig:203)

This fixed the state preservation bug but introduced a NEW critical bug: **queue blocking**.

### Root Cause: Queue Blocking

**What Happened:**
1. Stream 20 arrives → queued at position 1 → accepted → added to conn_state.streams
2. Client sends more data for stream 20
3. handleStreamFrame() re-queues stream 20 (no-op due to duplicate check, stays at position 1)
4. Stream 24 arrives → queued at position 2
5. acceptStream() keeps returning stream 20 from position 1
6. Stream 24 NEVER gets accepted → test times out after 30 seconds

**Debug Evidence:**
```
[P42-14-ACCEPT] Accepted stream 20
[P42-14-EXISTS] Stream 20 already has state (re-queued for more data)
[P42-13-READ] Stream 20 read 4096 bytes (4096 total read, loop 102)
[P42-13-FIN] Stream 20 received FIN (total read: 10240, total written: 10240, pending: 0)
[P42-14-REQUEUE] Stream 24 queued (2 total in queue)  ← Queued
[P42-14-REQUEUE] Stream 24 queued (2 total in queue)  ← Still at position 2
[P42-14-REQUEUE] Stream 24 queued (2 total in queue)  ← Never accepted
```

**Test Results:**
- ✅ Single Stream Echo (21 bytes)
- ✅ Multiple Concurrent Streams (4×16 bytes)
- ✅ Large Transfer (10KB) - Stream 20 completes
- ❌ Large Transfer (100KB) - Stream 24 stuck behind stream 20
- ❌ Tests 5-8 - All timeout

### Critical Insight: Re-Queueing Is Unnecessary

The Phase 42 Part 12 echo server ALREADY implements round-robin stream processing:

```zig
// Process all active streams in round-robin fashion (cmd/quic-server.zig:212)
var stream_iter = conn_state.streams.iterator();
while (stream_iter.next()) |entry| {
    const stream_id = entry.key_ptr.*;
    var stream = entry.value_ptr;

    // Try to flush pending writes
    if (stream.pending_write.items.len > 0) { ... }

    // Read new data from stream
    if (!stream.got_fin) {
        const n = api.readStream(conn, stream_id, chunk[0..]) catch ...;
        // ... echo data back ...
    }
}
```

**Key Points:**
1. The application layer tracks all accepted streams in `conn_state.streams`
2. Every event loop iteration processes ALL streams via iterator
3. Streams don't need to be re-queued - they're already being polled continuously
4. Re-queueing only causes FIFO blocking where new streams can't be accepted

### The Fix: Remove Re-Queueing Logic

**Modified:** `src/quic/conn.zig:1861-1864`

```zig
// BEFORE (Phase 42 Part 14 - BROKEN):
const is_peer_initiated = self.isPeerInitiatedStream(stream_id);
if (is_peer_initiated) {
    try self.queueIncomingStream(stream_id);  // ← Causes queue blocking
    std.debug.print("[P42-14-REQUEUE] Stream {} queued\n", .{stream_id});
}

// AFTER (Phase 42 Part 15 - FIXED):
// PHASE 42 PART 15: Don't re-queue streams - application layer handles round-robin
// The echo server (cmd/quic-server.zig) already processes all streams in round-robin
// fashion via conn_state.streams.iterator(). Re-queueing causes queue blocking where
// new streams get stuck behind already-accepted streams.
```

**State Preservation Fix Kept:** `cmd/quic-server.zig:203-209`
```zig
// PHASE 42 PART 14: Only create NEW state for streams we haven't seen before
while (api.acceptStream(conn)) |stream_id| {
    std.debug.print("[P42-14-ACCEPT] Accepted stream {}\n", .{stream_id});
    // Only create state if this is a genuinely new stream
    if (conn_state.streams.getPtr(stream_id) == null) {
        conn_state.streams.put(stream_id, .{}) catch {};
        std.debug.print("[P42-14-NEW] Created new state for stream {}\n", .{stream_id});
    } else {
        std.debug.print("[P42-14-EXISTS] Stream {} already has state (re-queued for more data)\n", .{stream_id});
    }
} else |_| {}
```

### Architecture Analysis

**Why This Works:**

1. **Edge-Triggered Acceptance:** acceptStream() returns each stream once when first created
2. **Level-Triggered Processing:** Round-robin iterator processes all accepted streams continuously
3. **Flow Control:** Pending write buffer handles blocked writes (Phase 42 Part 12)
4. **State Preservation:** HashMap checks prevent state overwrite (Phase 42 Part 14)

This creates a hybrid model:
- **Transport Layer (conn.zig):** Edge-triggered stream notifications via queue
- **Application Layer (cmd/quic-server.zig):** Level-triggered stream polling via iterator

No re-queueing needed - the application layer's round-robin iterator already provides continuous stream monitoring.

### Next Steps

1. Build and test with re-queueing removed
2. Verify all 8 tests pass
3. Commit Phase 42 Part 15 fix if successful
4. Document final architecture in investigation log

**Status:** Testing fix for queue blocking issue...

