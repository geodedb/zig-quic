# ztls TLS 1.3 Key Schedule Investigation

**Date:** 2025-11-13
**Context:** Phase 40 - TLS Secret Mismatch in quic-go Interoperability

## Problem Summary

The Zig QUIC server (using vendor/ztls) and Go quic-go client derive completely different TLS 1.3 handshake secrets from what should be identical inputs:

**Observed Secrets:**
```
Zig Server:
  Server HS = 6a53163dbf876ffde562afbae23a3c1b7a41ad76d085eea5a6084f82b7d82072
  Client HS = 870ee172be6c1aceccb0ee467d5f54597b04b671b162af82007c0776d7ad0039

Go Client:
  SERVER_HS = fb53f84b0ae802274803c5d2a909f6e85bbccba534225f72004ce59aeb4d3112
  CLIENT_HS = c8979acada231927a6b045379b7d5c059daa426b9ba302a4d712ea5f997e9e26
```

**Zero byte overlap** → Systematic issue, not a minor implementation bug.

## Investigation Steps Completed

### 1. Code Review of Key Schedule Implementation

**File:** `vendor/ztls/src/key_schedule.zig`

**Key Findings:**
- ✅ Uses Zig stdlib `std.crypto.kdf.hkdf.Hkdf` (HkdfSha256, HkdfSha384)
- ✅ Implements RFC 8446 §7.1 HKDF-Expand-Label correctly:
  ```zig
  // Encodes: [length:2][label_len:1]["tls13 " + label][context_len:1][context]
  ```
- ✅ RFC 9001 Appendix A.1 test vectors PASS (13/13 tests)
  - Initial secret derivation ✅
  - Client/server initial secret split ✅
  - Key/IV/HP derivation ✅

**Conclusion:** HKDF implementation is RFC-compliant and tested.

### 2. Transcript Hash Management Review

**File:** `vendor/ztls/src/tls13/transcript.zig`

**Key Findings:**
- ✅ Maintains dual SHA-256/SHA-384 hash states concurrently
- ✅ Updates transcript for each message in order
- ✅ Implements HelloRetryRequest special handling (RFC 8446 §4.4.1)
- ⚠️ Debug logging was DISABLED (now enabled)

**Transcript Update Flow:**
```zig
// Server side:
1. Client → ClientHello → transcript.update(ch_msg)      // processCrypto line 1037
2. Server builds ServerHello
3. Server → appendOutbound(.Initial, sh_msg, true)       // line 1862 - updates transcript
4. transcript_hash = transcript.finalize(.sha256)        // line 1864
5. derive handshake secrets using transcript_hash        // line 1865

// Client side:
1. Client sends ClientHello → transcript updated locally
2. Client ← ServerHello → processCrypto updates transcript // line 1037
3. Client derives handshake secrets
```

**Potential Issue:** Transcript update timing or message byte content differs.

### 3. Key Derivation Flow Review

**File:** `vendor/ztls/src/tls13/key_derivation.zig`

**Implementation:**
```zig
pub fn deriveHandshakeTraffic(hash: Hash, ecdhe_secret: []const u8, transcript_hash: Secret) {
    // RFC 8446 §7.1 key schedule:
    early_secret = HKDF-Extract(0, 0)              // No PSK
    empty_hash = Hash("")
    derived = Derive-Secret(early_secret, "derived", empty_hash)
    handshake_secret = HKDF-Extract(derived, ecdhe_secret)
    client_hs = Derive-Secret(handshake_secret, "c hs traffic", transcript_hash)
    server_hs = Derive-Secret(handshake_secret, "s hs traffic", transcript_hash)
}
```

**Inputs:**
1. **ECDHE shared secret** (32 bytes from X25519.scalarmult)
2. **Transcript hash** (SHA-256 hash of ClientHello || ServerHello)

**Potential Issues:**
- Different ECDHE shared secrets (key exchange mismatch)
- Different transcript hashes (message content mismatch)

### 4. Handshake Message Encoding Review

**File:** `vendor/ztls/src/tls13/context.zig:1843-1862`

**Server ServerHello Generation:**
```zig
const sh_body = try tls13_full.buildServerHello(
    allocator,
    server_random,          // 32 random bytes
    cipher_suite,           // TLS_AES_128_GCM_SHA256
    ch_view.key_share.group, // x25519
    server_pub[0..],        // 32-byte X25519 public key
    session_id_opt,         // Echo client's session_id if present
    null,                   // Extensions (minimal)
);
const sh_msg = try encodeHandshake(allocator, .server_hello, sh_body);
// sh_msg = [0x02][length:3][sh_body]
```

**Handshake Message Format (RFC 8446 §4):**
```
struct {
    HandshakeType msg_type;    // 1 byte
    uint24 length;             // 3 bytes
    select (Handshake.msg_type) {
        ...
    };
} Handshake;
```

**Potential Issue:** Encoding differences in ServerHello body (extensions, order, etc.)

## Hypothesis: Root Cause

Given zero byte overlap in secrets, the most likely cause is **different transcript hashes**:

### Scenario A: ServerHello Content Differs
- Server generates ServerHello with different extension order
- Or includes/excludes different extensions
- Or encodes values differently (e.g., session_id, key_share)

### Scenario B: ClientHello Interpretation Differs
- Server parses ClientHello differently
- Uses different subset of data for transcript

### Scenario C: Message Framing Differs
- Handshake message framing (4-byte header) differs
- Length fields encoded incorrectly

## Next Steps

### 1. Enable Debug Logging (DONE ✅)
```zig
// vendor/ztls/src/tls13/key_derivation.zig:64
const secret_trace_enabled = true;

// vendor/ztls/src/tls13/transcript.zig:74-75
const handshake_trace_enabled = true;
const secret_trace_enabled = true;
```

### 2. Capture Actual Values from Interop Test
Rebuild quic library with debug-enabled ztls:
```bash
cd ~/src/spyder/quic
zig build -Doptimize=Debug
make e2e-test-go-comprehensive 2>&1 | tee debug_output.log
```

Expected debug output:
```
[TRANSCRIPT] Adding ClientHello (0x01) len=XXX bytes, first 8: ...
[TRANSCRIPT] Full ClientHello message (XXX bytes): [hex dump]
[TRANSCRIPT] Adding ServerHello (0x02) len=XXX bytes, first 8: ...
[TRANSCRIPT] Full ServerHello message (XXX bytes): [hex dump]
[TRANSCRIPT] Finalized hash (32 bytes): ...
[TLS_KEY_SCHEDULE] Transcript hash (CH+SH): ...
[TLS_KEY_SCHEDULE] ECDHE shared secret: ...
[TLS_KEY_SCHEDULE] Client HS traffic secret: ...
[TLS_KEY_SCHEDULE] Server HS traffic secret: ...
```

### 3. Compare with Go Implementation
Extract TLS secrets from Go client:
```bash
# Go's SSLKEYLOGFILE already provides:
CLIENT_HANDSHAKE_TRAFFIC_SECRET ... c8979acada...
SERVER_HANDSHAKE_TRAFFIC_SECRET ... fb53f84b0a...
```

Compare:
1. Transcript hash values
2. ECDHE shared secrets
3. Early secret, derived secret, handshake secret (intermediate values)

### 4. Identify Exact Mismatch Point
- If ECDHE secrets match → transcript hash issue
- If ECDHE secrets differ → key exchange issue
- If intermediate values match but final secrets differ → label/context issue

### 5. Fix and Test
- Apply fix to identified issue
- Re-run interop test
- Verify secrets match
- Add regression test to prevent recurrence

## Test Coverage Status

**RFC Test Vectors:** ✅ PASS (13/13)
- RFC 9001 Appendix A.1: Initial secret derivation
- HKDF-Expand-Label with various labels and contexts
- Traffic secret updates

**Conformance Tests:** ⚠️ IN PROGRESS
- Created: `tests/conformance/handshake_secrets.zig`
- Status: Build errors (OpenSSL HKDF functions not exported)
- Alternative: Compare against known TLS 1.3 handshake traces

**Unit Tests:** ✅ PASS (262/262)
- key_schedule.zig: 15 tests
- transcript.zig: 8 tests
- key_derivation.zig: (included in tls13 module tests)

## References

- **RFC 8446 §7.1:** TLS 1.3 Key Schedule
- **RFC 9001 §5:** QUIC Packet Protection
- **RFC 9001 Appendix A.1:** Test Vectors
- **Investigation Log:** `~/src/spyder/quic/E2E_TEST_INVESTIGATION.md` Phase 40

## Timeline

- **2025-11-13 07:37:** Issue discovered - client fails to decrypt Handshake packet
- **2025-11-13 [Current]:** Deep dive into ztls key schedule implementation
- **Next:** Capture debug logs from live interop test

---

**Status:** 🔄 **IN PROGRESS** - Awaiting debug log capture from interop test
