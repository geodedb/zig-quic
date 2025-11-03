# QUIC Handshake Interop Issue with quic-go

**Date**: November 3, 2025  
**Status**: **IDENTIFIED - REQUIRES DEEP CRYPTO DEBUGGING**  
**Impact**: Prevents full handshake completion with quic-go clients

---

## Issue Summary

The QUIC server successfully exchanges Initial packets with quic-go clients but **Handshake packets cannot be decrypted by the client**, causing connection timeout after ~5 seconds.

### What Works ✓

1. **Initial Packet Exchange**: Complete and correct

   - Server receives ClientHello from quic-go client
   - Server derives keys and sends ServerHello in Initial packet (90 bytes)
   - Client successfully decrypts and processes ServerHello
   - RFC 9000 §7.2 compliance: Zero-length DCIDs used correctly

2. **Handshake Packet Transmission**: Packets are sent

   - Server sends 4 separate Handshake packets (607 bytes total CRYPTO)
   - Packets use correct DCID length (0 for zero-SCID clients)
   - Minimal varint encoding per RFC 9000 §17.2
   - Client receives all 4 packets

3. **Stream Support**: Fully implemented and working
   - Bi-directional stream open/accept/read/write
   - Flow control and MAX_STREAM_DATA handling
   - STREAM frame encoding/decoding
   - Stream state management

### What Fails ✗

**Handshake Packet Decryption**: quic-go client cannot decrypt our Handshake packets.

**Evidence**:

```
# Client logs show:
[UNPACKER] Unpacking long header packet: type=Handshake
[UNPACKER] Processing Handshake packet
# NO [CRYPTO_MGR] messages follow - decryption failed
# Client times out: "Failed to dial: timeout: no recent network activity"
```

**Root Cause**: Cryptographic incompatibility - one or more of:

1. **Transcript Hash Mismatch**  
   Our TLS implementation computes a different hash than quic-go when deriving Handshake traffic secrets. The hash should be `SHA256(ClientHello || ServerHello)`.

2. **AEAD Encryption Error**

   - Wrong nonce construction (should be `IV ⊕ PacketNumber`)
   - Incorrect AAD (Additional Authenticated Data)
   - Key/IV derivation differs from RFC 9001 §5.1

3. **Header Protection Error**

   - Sample offset calculation wrong (RFC 9001 §5.4.2)
   - Mask application incorrect
   - PN encoding/expansion mismatch

4. **Packet Number Issues**
   - Truncated PN encoding differs from expected
   - PN reconstruction algorithm mismatch

---

## Technical Details

### Key Derivation

Server derives Handshake keys using:

```
transcript_hash = SHA256(ClientHello || ServerHello)
handshake_secret = HKDF-Extract(ECDHE_secret, salt)
client_hs_secret = HKDF-Expand-Label(handshake_secret, "c hs traffic", transcript_hash)
server_hs_secret = HKDF-Expand-Label(handshake_secret, "s hs traffic", transcript_hash)
```

Then derive QUIC keys per RFC 9001 §5.1:

```
key = HKDF-Expand-Label(hs_secret, "quic key", "")
iv  = HKDF-Expand-Label(hs_secret, "quic iv", "")
hp  = HKDF-Expand-Label(hs_secret, "quic hp", "")
```

### Handshake Packet Structure

```
Header: (long-form, type=2)
  - Flags: 0xEX (type=2, key_phase=0, reserved=0)
  - Version: 0x00000001
  - DCID len: 0 (for zero-SCID clients)
  - DCID: (empty)
  - SCID len: 8
  - SCID: [8 random bytes]
  - Length: [varint] (payload + PN + AEAD tag)
  - PN: [2-4 bytes, truncated]

Payload: (encrypted with Handshake keys)
  - CRYPTO frames containing:
    * EncryptedExtensions (87 bytes)
    * Certificate (variable)
    * CertificateVerify (variable)
    * Finished (36 bytes)

AEAD Tag: 16 bytes (AES-128-GCM)

Header Protection: Applied to first byte + PN bytes using HP key
```

### Comparison with Working Initial Packets

| Aspect              | Initial                   | Handshake                       |
| ------------------- | ------------------------- | ------------------------------- |
| Key derivation      | Initial secrets from DCID | Traffic secrets from transcript |
| Client can decrypt? | ✓ YES                     | ✗ NO                            |
| Sample offset       | 4 - pn_len                | 4 - pn_len                      |
| AEAD algorithm      | AES-128-GCM               | AES-128-GCM                     |
| Nonce construction  | IV ⊕ PN                   | IV ⊕ PN                         |

---

## Debugging Approach (Next Steps)

### 1. Add Known Answer Tests (KAT)

Create test with RFC 9001 Appendix A vectors:

- Verify our Initial packet encoding matches RFC examples byte-for-byte
- Add Handshake packet test vectors if available
- Test HKDF-Expand-Label against RFC 8446 examples

### 2. Transcript Hash Verification

Add logging to compare:

```zig
std.debug.print("ClientHello hash: {x}\n", .{std.fmt.fmtSliceHexLower(&ch_hash)});
std.debug.print("CH+SH hash: {x}\n", .{std.fmt.fmtSliceHexLower(&transcript)});
```

Capture quic-go's transcript hash using SSLKEYLOGFILE and compare.

### 3. Key Material Export

Log derived secrets (SECURITY: only for debugging):

```zig
std.debug.print("server_hs_secret: {x}\n", .{std.fmt.fmtSliceHexLower(&secret)});
std.debug.print("server_hs_key: {x}\n", .{std.fmt.fmtSliceHexLower(&key)});
std.debug.print("server_hs_iv: {x}\n", .{std.fmt.fmtSliceHexLower(&iv)});
```

Compare with quic-go's SSLKEYLOGFILE output.

### 4. Packet Hex Dump

Capture and compare encrypted Handshake packets:

```bash
sudo tcpdump -i lo port 4433 -w handshake_capture.pcap
wireshark handshake_capture.pcap
```

Manually verify:

- Header format matches RFC 9000 §17.2
- Sample offset is correct (4 - pn_len from start of PN field)
- AEAD tag is present (last 16 bytes)

### 5. Test with Other Implementations

Try interop with:

- **quiche** (Rust): More detailed error messages
- **ngtcp2** (C): Known-good reference implementation
- **picoquic** (C): Simpler codebase for comparison

---

## Workaround

For testing stream functionality without full Handshake completion:

1. **Self-test**: Connect Zig client to Zig server (both use same crypto)
2. **Mock mode**: Skip TLS verification for local testing
3. **Alternative client**: Use `curl --http3` or `h2load` if they work

---

## Impact on Project

**Current Capabilities**:

- ✓ Initial packet exchange (Initial keys work)
- ✓ Zero-length DCID support
- ✓ Stream API (open/accept/read/write)
- ✓ Flow control and framing
- ✓ Packet coalescing
- ✓ Loss detection skeleton

**Blocked by This Issue**:

- ✗ Full handshake with external clients
- ✗ Application data transfer (requires 1-RTT keys)
- ✗ Real-world interoperability testing

**Estimated Fix Effort**: 4-8 hours of crypto debugging + testing

---

## References

- RFC 9000: QUIC Transport Protocol
- RFC 9001: Using TLS to Secure QUIC (esp. §5 Packet Protection)
- RFC 8446: TLS 1.3 (Key Schedule)
- quic-go source: `github.com/quic-go/quic-go`
- Test vectors: RFC 9001 Appendix A

---

## Test Reproduction

```bash
# Start server
cd /home/benji/src/spyder/quic
./zig-out/bin/quic-server 127.0.0.1:4433 --cert server.crt --key server.key

# Run quic-go client (in another terminal)
cd test-clients/quic-go-client
./quic-go-test-client 127.0.0.1:4433

# Expected: Timeout after ~5 seconds
# Logs: /tmp/server_test.log, /tmp/quic_go_test.log
```

---

**Conclusion**: This is a solvable but time-intensive cryptographic debugging problem. The infrastructure is in place (keys derive, packets send), but there's a subtle incompatibility in how we protect/encrypt Handshake packets compared to quic-go's expectations.
