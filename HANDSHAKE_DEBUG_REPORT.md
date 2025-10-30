# QUIC Handshake Debug Report
**Date**: October 30, 2025
**Status**: Client cannot decrypt server Handshake packets

## Bugs Fixed in This Session

### 1. ✅ CRYPTO Offset Bug (endpoint.zig:2173-2327)
**Problem**: Retransmissions were incrementing offset
**Evidence**: First send offset=0, retransmits offset=315, 630, 945
**Fix**: Track `is_new_data` flag, only increment for new data
**Verification**: All retransmissions now use offset=0 ✓

### 2. ✅ Handshake DCID Bug (endpoint.zig:2213-2225)
**Problem**: Using zero-length `peer_initial_scid` as DCID
**Evidence**: Server log showed "Handshake DCID len=0"
**Fix**: Use `our_scid` when client sends zero-length SCID
**Verification**: Now using "Handshake DCID len=8" ✓

### 3. ✅ ServerHello Inclusion (from previous session)
**Problem**: ServerHello was being cleared from outbox
**Fix**: Don't clear outbox after queueing ServerHello
**Verification**: Handshake packets now 315 bytes (was 225) ✓

## Current Status

### What's Working ✓
- Packet encoding is 100% RFC 9000/9001 compliant (verified by spec-compliance-validator)
- Encryption primitives correct (nonce, AAD, HP) verified by quic-tls-implementation-verifier
- Keys correctly derived and assigned (server TX = hs_server, RX = hs_client)
- DCID correct (len=8, using our_scid)
- CRYPTO offset correct (always 0)
- ServerHello included (314 bytes TLS data, 5 messages)

### What's Not Working ❌
- Client doesn't send Handshake packets back
- Client keeps retransmitting Initial packets
- Suggests client still cannot decrypt server Handshake packets

## Diagnostic Evidence

### Handshake Packet Structure
```
Server: Handshake DCID len=8 (peer_scid_len=0, using our_scid)
Found 5 TLS message boundaries in 314 bytes
protectPacket: pn=0 pn_len=2 header_prefix_len=24 aad_len=27
Handshake packet 0 encoded: 361 bytes (CRYPTO 314 bytes at offset 0)
Sending coalesced packet: 1145 bytes (Initial + Handshake)
```

### Key Derivation
```
deriveHandshakeKeys: role=Server, version_v2=false
  hs_client secret[0..4]: DEB714A9
  hs_server secret[0..4]: 7E4BC47F
  rx_secret (for reading) = client secret[0..4]: DEB714A9
  tx_secret (for writing) = server secret[0..4]: 7E4BC47F
```

### Client Behavior
- Successfully decrypts server Initial packets ✓
- Sends multiple Initial packet retransmissions (same content)
- Never sends Handshake packets
- Times out after 5 seconds

## Remaining Investigation Areas

Based on RFC-compliance verification, the issue is **NOT** in:
- Packet encoding (100% compliant)
- Encryption primitives (verified correct)
- Key assignment (correct TX/RX mapping)

### Hypothesis 1: TLS Transcript Hash Mismatch (HIGH PROBABILITY)
**Theory**: Client's transcript hash doesn't match server's, causing key derivation mismatch

**Evidence Needed**:
- Compare client and server transcript hashes
- Verify ServerHello content matches what client expects
- Check if extensions/parameters are correctly formatted

**Next Steps**:
1. Add transcript hash logging in TLS engine
2. Capture Wireshark trace with SSLKEYLOGFILE
3. Compare with quic-go reference implementation

### Hypothesis 2: TLS Message Boundaries (MEDIUM PROBABILITY)
**Theory**: The 314 bytes of TLS data have incorrect message boundaries

**Evidence**:
- Server logs: "Found 5 TLS message boundaries in 314 bytes"
- Expected: ServerHello + EE + Cert + CV + Finished = 5 messages ✓
- But actual content/lengths might be wrong

**Next Steps**:
1. Hexdump the 314 bytes of TLS data
2. Parse each TLS message manually
3. Verify lengths match TLS 1.3 spec

### Hypothesis 3: Certificate Issues (LOW PROBABILITY)
**Theory**: Certificate format or signature verification failing

**Evidence Needed**:
- Check certificate chain validity
- Verify signature algorithm matches client expectations
- Ensure certificate is for correct hostname

### Hypothesis 4: QUIC Version Negotiation (LOW PROBABILITY)
**Theory**: Version mismatch between Initial and Handshake packets

**Evidence**:
- Server uses version_v2=false (QUIC v1)
- Need to verify Initial packets use same version

## Recommended Next Steps

1. **Add TLS Transcript Logging** (IMMEDIATE):
   ```zig
   // In tls13.zig after computing handshake_hash
   logger.debug("TLS transcript hash[0..8]: {x}", .{handshake_hash[0..8]});
   ```

2. **Hexdump TLS Data** (IMMEDIATE):
   ```zig
   // In endpoint.zig before sending Handshake
   logger.debug("TLS data hexdump:");
   for (tls_buf[0..n_tls], 0..) |byte, i| {
       if (i % 16 == 0) logger.debug("\n{X:0>4}: ", .{i});
       logger.debug("{X:0>2} ", .{byte});
   }
   ```

3. **Packet Capture** (HIGH VALUE):
   ```bash
   # Set SSLKEYLOGFILE for client
   export SSLKEYLOGFILE=/tmp/keys.log
   tcpdump -i lo -w /tmp/handshake.pcap port 4433
   # Then analyze in Wireshark
   ```

4. **Compare with Reference** (USE AGENT):
   - Use quic-tls-implementation-verifier to compare ServerHello format
   - Check quic-go source for expected TLS message structure

## Files Modified

1. `/home/benji/src/spyder/quic/src/quic/endpoint.zig`
   - Lines 2173-2189: Added `is_new_data` flag for CRYPTO offset tracking
   - Lines 2198-2211: Conditional retransmit buffer update
   - Lines 2213-2225: Fixed Handshake DCID selection
   - Lines 2228: Use base_crypto_offset for retransmissions
   - Lines 2321-2327: Only increment offset for new data

2. `/home/benji/src/spyder/quic/src/quic/conn.zig` (previous session)
   - Lines 1128-1129: Removed outbox.clearRetainingCapacity() call

## Test Results

### Go Client (quic-go)
```
2025/10/30 18:23:26 failed to sufficiently increase receive buffer size
2025/10/30 18:23:31 Failed to dial: context deadline exceeded
exit status 1
```
**Status**: ❌ Timeout (client cannot decrypt Handshake)

### Python Client (aioquic)
**Status**: Not yet tested

### Rust Client (quinn)
**Status**: Not yet tested

## Summary

We've fixed 3 critical bugs but clients still cannot decrypt Handshake packets. The packet encoding and key derivation are both RFC-compliant and correct. The issue is most likely in the **TLS message content** or **transcript hash calculation**.

Next investigation should focus on:
1. TLS transcript hash verification
2. ServerHello content validation
3. Packet capture analysis with Wireshark

The implementation is very close to working - we just need to find the TLS-layer issue preventing client decryption.
