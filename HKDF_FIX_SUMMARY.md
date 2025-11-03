# HKDF Bug Fix Summary - 2025-11-03

## Critical Bug Fixed

### Root Cause
The TLS 1.3 key derivation was using **empty arrays** (`&[_]u8{}`) instead of **32-byte zero arrays** when deriving the early secret.

### The Fix
**File:** `src/quic/tls/tls13.zig` (line 1364-1373)

**Before (BROKEN):**
```zig
const early_secret = ks.extract(&[_]u8{}, &[_]u8{});
ks.expandLabel(early_secret, "derived", &[_]u8{}, &derived) catch unreachable;
```

**After (FIXED):**
```zig
// RFC 8446 §7.1: If a given secret is not available, then the 0-value
// consisting of a string of Hash.length bytes set to zeros is used.
const zero_value = [_]u8{0} ** H.digest_length; // 32 zero bytes for SHA-256
const early_secret = ks.extract(&zero_value, &zero_value);

// RFC 8446 §7.1: The context for "derived" is Hash("")
var empty_hash: [H.digest_length]u8 = undefined;
H.hash(&[_]u8{}, &empty_hash, .{});
ks.expandLabel(early_secret, "derived", &empty_hash, &derived) catch unreachable;
```

### Impact
**Before Fix:**
- Server computed: Client HS `4D7C8496...`, Server HS `D265BF39...`
- Client computed: Write HS `17E27E89...`, Read HS `C1E0C9CF...`
- Complete mismatch → clients couldn't decrypt Handshake packets

**After Fix:**
- Python verification confirms both server and client now compute identical handshake secrets
- ✅ All three QUIC clients (quic-go, aioquic, quinn) can now:
  - Decrypt ServerHello packets
  - Decrypt Handshake packets
  - Process CRYPTO frames successfully

## Test Results

```
Tests Run:    3
Tests Passed: 3
Tests Failed: 0
```

All clients successfully:
1. Complete Initial exchange (ServerHello decryption) ✅
2. Install Handshake keys ✅
3. Decrypt Handshake CRYPTO frames ✅

## Remaining Issue

**Current Error (all clients):**
```
quic-go:  "received unexpected handshake message of type *tls.finishedMsg when waiting for *tls.certificateMsgTLS13"
aioquic:  "CRYPTO_ERROR 0x10a (unexpected_message)"
quinn:    "received unexpected handshake message: got Finished when expecting Certificate or CertificateRequest"
```

**Diagnosis:**
The server is sending handshake messages in the wrong order:
1. ✅ ServerHello (Initial)
2. ✅ EncryptedExtensions (Handshake) - 88 bytes observed
3. ❌ **Finished (Handshake) - 36 bytes observed** ← WRONG ORDER
4. ❌ **Certificate - MISSING**
5. ❌ **CertificateVerify - MISSING**

**Correct RFC 8446 Order:**
1. ServerHello
2. EncryptedExtensions
3. **Certificate** ← Should come before Finished
4. **CertificateVerify** ← Should come before Finished
5. Finished

## Next Steps

1. **Investigate why Certificate/CertificateVerify are not being sent:**
   - Check if `server_cert_der` and `server_priv_key` are properly set in TLS engine
   - Add logging to `queueServerHandshakeFlight()` to confirm execution path
   - Verify certificate loading in `api.zig` is properly calling `engine.setServerCertAndKey()`

2. **Verify handshake flight ordering:**
   - Ensure `queueServerHandshakeFlight()` queues all messages in correct order
   - Confirm endpoint.zig calls this function at the right time
   - Check that CRYPTO frames are transmitted in order

3. **Test bi-directional data streaming:**
   - Once handshake completes, verify stream data can flow both ways
   - Test with all three client implementations

## Files Modified

- `src/quic/tls/tls13.zig` (lines 1364-1373): Fixed HKDF early_secret derivation

## References

- RFC 8446 §7.1: Key Schedule
- RFC 8446 §4.4: Handshake Protocol
- RFC 9001 §4: QUIC Handshake
