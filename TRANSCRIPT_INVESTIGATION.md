# QUIC TLS 1.3 Transcript Hash Investigation

## Current Status

### ✅ What's Working
1. **Handshake traffic secrets MATCH** between server and Go client
   - Server CLIENT_HANDSHAKE: `AD4981ABED276683ED41433CE8556B4567E1CE6EA19996A0EC32D13506208800`
   - Go client: `ad4981abed276683ed41433ce8556b4567e1ce6ea19996a0ec32d13506208800`
   - This proves ClientHello + ServerHello are IDENTICAL

2. **HKDF implementation is CORRECT**
   - Python verification matches server output byte-for-byte
   - master_secret derivation is correct

3. **Transcript sequence is CORRECT**
   - Server Finished is added to transcript before computing app secrets ✅
   - Client Finished is NOT in transcript when computing app secrets ✅
   - No extra messages are added between server Finished and app secret computation ✅

4. **handshake_secret caching bug FIXED**
   - Now using cached value instead of recomputing from ECDHE
   - Handshake secrets now consistently match

### ❌ What's NOT Working
**Application traffic secrets MISMATCH:**
- Server derives CLIENT_APP: `DD2F0CA8F0D5F9A49D55219BC36CEEAFF7A97E011A8C9DA8EFF0BEA706AFC5CE`
- Go client CLIENT_APP: `9C09D43694B7540C6AD16B9E2164930884C67AB37C291B19C77BE2E3D789D82E`
- Server derives SERVER_APP: `2F18F7C61D487F54058E88CDE201B831A882A4510D4EF1B2C6A894DC4D000BAE`
- Go client SERVER_APP: `45911F291CDCBC8A5BEE73DBAED420F7664F83DD061F9FFAAF9D7D9FD70774B0`

## Root Cause Analysis

Since:
1. Handshake secrets match → ClientHello + ServerHello are correct
2. HKDF is correct → Crypto implementation is sound
3. Transcript sequence is correct → Timing/ordering is right
4. handshake_secret is correct → Key schedule is working

**The ONLY remaining explanation:**
> The **CONTENT** of one or more messages after ServerHello differs between what our server adds to transcript and what the Go client receives and adds to its transcript.

## Messages Under Suspicion

The transcript for application secrets includes:
1. ✅ ClientHello (1502 bytes with header) - **VERIFIED CORRECT** (handshake secrets match)
2. ✅ ServerHello (90 bytes with header) - **VERIFIED CORRECT** (handshake secrets match)
3. ❓ EncryptedExtensions (99 bytes with header)
4. ❓ Certificate (398 bytes with header)
5. ❓ CertificateVerify (80 bytes with header)
6. ❓ server Finished (36 bytes with header)

One of messages 3-6 has different bytes than what the Go client receives.

## Server's Transcript Hash
```
6ADBDBE3595BCFE0E0912F6E6D8BC4AEB97544971CD21666EF04C5B0FB468EB2
```

This produces:
- CLIENT_APP: `DD2F0CA8...` (server's value)

## Go Client's Transcript Hash
**Unknown** - but it produces:
- CLIENT_APP: `9C09D43694...` (different from server)

## Potential Causes

### 1. EncryptedExtensions Content Mismatch
- **ALPN**: Server sends "hq-interop", client might expect something else
- **QUIC transport parameters**: Mismatch in advertised values
- **Extensions ordering**: Different order than client expects
- **Extension encoding**: Off-by-one or encoding bug

### 2. Certificate Encoding Issue
- DER encoding difference
- Certificate chain ordering
- Context byte (should be 0x00 for server cert)

### 3. CertificateVerify Signature
- Signature algorithm mismatch
- Signature encoding (DER vs raw)
- Message padding or context string

### 4. Finished Message
- verify_data computation bug (but this is just HMAC)
- Message structure (should be simple: type + length + verify_data)

## Server's Message Bytes (from log)

### EncryptedExtensions (99 bytes total)
```
08 00 00 5F 00 5D 00 10 00 0D 00 0B 0A 68 71 2D
69 6E 74 65 72 6F 70 00 39 00 48 01 04 80 00 75
30 04 04 80 04 00 00 03 02 45 46 05 04 80 01 00
00 06 04 80 01 00 00 07 04 80 01 00 00 08 01 10
09 01 00 00 14 FB 50 BD 63 D0 A4 F2 D8 C0 A7 D5
37 61 E4 35 CE 3F FD 44 1B 0F 08 A4 F0 2B 85 BA
85 FE 1F
```
Breakdown:
- `08 00 00 5F` - Type (EE) + length (95)
- `00 5D` - Extensions length (93)
- `00 10 00 0D 00 0B 0A 68 71 2D 69 6E 74 65 72 6F 70` - ALPN: "hq-interop"
- `00 39 00 48 ...` - QUIC transport parameters (extension 0x0039, length 0x0048=72)

### server Finished (36 bytes total)
```
14 00 00 20 D1 56 AA 99 BB 96 69 7C B2 2A 87 0D
01 E9 59 EF A0 8E 80 E3 67 72 82 9C 33 BF DF 6C
23 0D 0F 10
```
- `14 00 00 20` - Type (Finished) + length (32)
- 32 bytes of verify_data

## Next Investigation Steps

### Option 1: Packet Capture Analysis
Use Wireshark/tcpdump to capture actual packets sent by our server:
```bash
tcpdump -i lo -w /tmp/quic.pcap port 4433
# Then use Wireshark to extract TLS handshake messages
```

### Option 2: Test with Different Client
Try connecting with a different QUIC implementation (quiche, aioquic, etc.) to see if the issue is specific to quic-go or affects all clients.

### Option 3: Message-by-Message Comparison
Extract each message from our transcript and compare with what a reference implementation (BoringSSL/quiche) would generate for the same inputs.

### Option 4: Add Debug Logging to Go Client
Modify quic-go to log its transcript hash before computing application secrets, then compare directly with our server's hash.

### Option 5: QUIC Frame Inspection
Verify that CRYPTO frames are correctly extracting TLS messages without including QUIC frame headers in the transcript.

## Hypothesis Priority

**Most Likely (70%)**: EncryptedExtensions content mismatch
- QUIC transport parameters are complex and easy to get wrong
- Extensions might be in wrong order or have encoding issues

**Likely (20%)**: CertificateVerify encoding issue
- ECDSA signature encoding is tricky (DER format)
- Context string for TLS 1.3 signatures is specific

**Possible (8%)**: Certificate encoding
- Less likely since it's mostly pass-through of DER cert
- But certificate_request_context byte could be wrong

**Unlikely (2%)**: Finished message
- Very simple structure, hard to get wrong
- But verify_data computation could have subtle bug

## Files to Investigate

1. `/home/benji/src/spyder/quic/src/quic/tls/tls13.zig`
   - `queueEncryptedExtensions()` - Line ~2900
   - `queueCertificate()` - Line ~3100
   - `queueCertificateVerify()` - Line ~3200
   - `queueFinished()` - Line ~3300

2. `/home/benji/src/spyder/quic/forks/boringssl/` - Reference implementation
3. `/home/benji/src/spyder/quic/forks/quiche/` - Reference implementation

## Action Plan

1. **Immediate**: Capture packets and extract actual TLS handshake messages from wire
2. **Immediate**: Compare our EncryptedExtensions with quiche/BoringSSL reference
3. **Short-term**: Add more detailed logging to show full message bytes for all 4 suspect messages
4. **Short-term**: Test with aioquic or another Python QUIC client
5. **If needed**: Manually compute transcript hash from captured packets to verify
