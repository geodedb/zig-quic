# OpenSSL Integration Status

**Date**: 2025-11-05
**Status**: PARTIAL - OpenSSL integrated but decryption still failing

---

## What Was Completed

### 1. OpenSSL Bindings Created ✅
- **File**: `src/quic/crypto_openssl.zig`
- **API**: Standard OpenSSL 3.x EVP API (not BoringSSL-specific)
- **Functions**:
  - `aeadEncrypt()` - AEAD encryption
  - `aeadDecrypt()` - AEAD decryption
  - `headerProtect()` - AES-ECB header protection
  - `makeNonce()` - RFC 9001-compliant nonce computation

### 2. Build System Updated ✅
- **File**: `build.zig`
- **Changes**:
  - `addExe()` now links `-lssl -lcrypto -lc`
  - `addTst()` now links OpenSSL for tests
  - All executables and tests have OpenSSL available

### 3. OpenSSL Verification ✅
**Test**: `/tmp/openssl_test.log`

```
Test 1: OpenSSL round-trip (encrypt then decrypt)
Plaintext: "GET /\r\n" (7 bytes)
Encrypted CT: b0ebf354d101a5
Result: ✓ SUCCESS - Decrypted correctly
```

### 4. Zig vs OpenSSL Comparison ✅
**Critical Finding**:
```
Zig std.crypto AES-128-GCM:     CT = b0ebf354d101a5
OpenSSL 3.x AES-128-GCM:        CT = b0ebf354d101a5
                                     ^^^^^^^^^^^^^^
                                     IDENTICAL!
```

**This proves**: Zig and OpenSSL are fully compatible!

---

## The Real Problem

### OpenSSL CANNOT Decrypt quic-go's Ciphertext Either!

```
Test 2: Decrypt quic-go ciphertext with OpenSSL
Expected CT from packet: abbccf28d86e25
Result: ❌ AuthenticationFailed
```

### Analysis

Both Zig and OpenSSL:
1. ✅ Produce identical ciphertext when encrypting "GET /\r\n"
2. ✅ Successfully decrypt their own ciphertext
3. ❌ FAIL to decrypt quic-go's ciphertext

**Conclusion**: The issue is NOT with Zig's crypto or OpenSSL compatibility.

---

## Remaining Hypotheses

### Hypothesis 1: Wrong Keys
**Likelihood**: MEDIUM

Server derives:
```
RX secret[0..8]: 46 62 85 62 92 27 E8 09
RX key[0..8]:    08 C9 BE DE 96 F5 7D CD
RX iv[0..8]:     D1 66 9E 59 E0 15 B9 99
```

**Need to verify**: Do these match what quic-go client is using for TX?

**Action**: Add key logging to Go client to export TLS traffic secrets.

### Hypothesis 2: Wrong Plaintext
**Likelihood**: LOW

Ciphertext length: 7 bytes
→ Plaintext length: 7 bytes (GCM is a stream cipher)

"GET /\r\n" is 7 bytes, but could be:
- Just the string: "GET /\r\n"
- STREAM frame?: Impossible - frame headers alone are 1-2 bytes
- Different data?: What else would the client send?

### Hypothesis 3: Wrong AAD
**Likelihood**: LOW

AAD constructed per RFC 9001 §5.4.1:
```
AAD: 53 4E CC A1 6F 10 B7 79 B0 2A A1 EB 9B (13 bytes)
     ^^---DCID (8B)---^^  ^^--PN (4B)--^^
```

Verified correct against reference implementations.

### Hypothesis 4: Wrong Nonce
**Likelihood**: LOW

Nonce = IV XOR PN (RFC 9001 §5.3):
```
IV:     D1 66 9E 59 E0 15 B9 99 55 A6 AB 48
PN:     00 00 00 00 2A A1 EB 9B (715254683)
Nonce:  D1 66 9E 59 E0 15 B9 99 7F 07 40 D3
```

Matches quiche's implementation exactly.

### Hypothesis 5: Packet Structure Misunderstanding
**Likelihood**: HIGH

Maybe we're extracting the wrong 7 bytes as ciphertext?

**From packet** (36 bytes total):
```
5F 4E CC A1 6F 10 B7 79 B0 7A 5E D7 EE AB BC CF 28 D8 6E 25 F6 2B 1C F3 DC 85 D2 66 92 2B C2 C7 97 BB 68 10

After HP removal:
Header: 53
DCID:   4E CC A1 6F 10 B7 79 B0
PN:     2A A1 EB 9B

Byte 13 onwards:
AB BC CF 28 D8 6E 25 F6 2B 1C F3 DC 85 D2 66 92 2B C2 C7 97 BB 68 10
```

**Current extraction**:
- CT (7B): `AB BC CF 28 D8 6E 25`
- Tag (16B): `F6 2B 1C F3 DC 85 D2 66 92 2B C2 C7 97 BB 68 10`

**Question**: Is this correct? Or should CT/tag boundaries be different?

---

## Next Steps (Priority Order)

### IMMEDIATE (30 minutes - 1 hour)

#### 1. Add TLS Key Logging to Go Client
**File**: `quic-test/test_client.go`

Add:
```go
import "os"

// After creating tls.Config:
keyLogFile, _ := os.Create("/tmp/tls_keys.log")
tlsConf.KeyLogWriter = keyLogFile
```

This will export:
- `CLIENT_HANDSHAKE_TRAFFIC_SECRET`
- `SERVER_HANDSHAKE_TRAFFIC_SECRET`
- `CLIENT_TRAFFIC_SECRET_0` ← **This is what we need!**
- `SERVER_TRAFFIC_SECRET_0`

Compare with server's derived secrets.

#### 2. Verify Ciphertext Extraction
Double-check packet.zig decodeShortProtected():
- Is `pn_start + pn_len` the correct CT offset?
- Are we reading CT length correctly?
- Is tag really the last 16 bytes?

#### 3. Wireshark Analysis
```bash
sudo tcpdump -i lo -w /tmp/quic.pcap 'port 4433'
# Run test
wireshark /tmp/quic.pcap
```

With TLS keys from step 1, Wireshark can decrypt and show:
- Actual ciphertext boundaries
- Actual plaintext content
- Whether our extraction is correct

### MEDIUM-TERM (2-4 hours)

#### 4. Replace crypto_quic.zig with crypto_openssl.zig
Once we fix the parameter mismatch:
```zig
// In crypto_quic.zig, replace:
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

// With:
const openssl = @import("crypto_openssl.zig");
pub const aeadDecrypt = openssl.aeadDecrypt;
pub const aeadEncrypt = openssl.aeadEncrypt;
```

#### 5. Full Integration Test
```bash
zig build
make e2e-test-go-comprehensive 2>&1 | tee /tmp/final-test.log
```

---

## Files Modified

### Created
- `src/quic/crypto_openssl.zig` - OpenSSL AEAD bindings
- `OPENSSL_INTEGRATION_STATUS.md` - This document
- `/tmp/test_stream_frame.zig` - Plaintext format tests

### Modified
- `build.zig` - Added OpenSSL linking to `addExe()` and `addTst()`

### To Modify
- `quic-test/test_client.go` - Add KeyLogWriter
- `src/quic/crypto_quic.zig` - Switch to OpenSSL backend

---

## Key Insight

**Zig's crypto was NEVER the problem!**

The real issue is either:
1. Key mismatch between client and server
2. Packet structure misunderstanding
3. Unknown quic-go implementation detail

OpenSSL integration proves the crypto libraries are compatible, but we still need to debug the parameter mismatch.

---

## Test Results Summary

| Test | Implementation | Result |
|------|---------------|--------|
| Round-trip | Zig std.crypto | ✅ PASS |
| Round-trip | OpenSSL 3.x | ✅ PASS |
| Zig vs OpenSSL | Comparison | ✅ IDENTICAL |
| Decrypt quic-go | Zig | ❌ FAIL |
| Decrypt quic-go | OpenSSL | ❌ FAIL |

**Takeaway**: Switching to OpenSSL won't fix the bug because OpenSSL also can't decrypt quic-go's ciphertext with our current parameters.

We need to find the parameter mismatch first.
