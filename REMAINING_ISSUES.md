# Remaining QUIC/TLS Issues

**Date**: October 30, 2025 (Updated 15:21)
**Status**: Initial packet decryption failure - AEAD auth fails, header unprotection produces invalid PN

---

## ✅ Fixed Issues

### 1. Event Loop Busy-Wait (RESOLVED)
- Removed `poll(ep, 0)` tight loop causing 100% CPU
- Implemented proper event-driven I/O with `poll(ep, 20)` and reasonable timeout
- Modified `cmd/quic-server.zig` lines 147-200

### 2. Initial Key Caching (RESOLVED)
- Added key caching to Connection struct to prevent re-derivation on retransmits
- Added `initial_rx_keys` and `initial_tx_keys` fields in `src/quic/conn.zig`
- Caching logic in `src/quic/endpoint.zig` lines 1740-1747, 2114-2120

### 3. RETRY Cascade Problem (RESOLVED)
- Removed incorrect RETRY sending on decryption failures
- RETRY is for DoS protection, not authentication failures
- Modified `src/quic/endpoint.zig` lines 1860-1870 to drop invalid packets silently

---

## ❌ CURRENT ISSUE: Initial Packet AEAD Decryption Failure

### Symptoms
- ✅ Server binds to 127.0.0.1:4433
- ✅ Socket receives UDP packets from Go client (1280 bytes each)
- ✅ epoll triggers correctly
- ✅ `drainReadable()` and `processIncomingDatagram()` called successfully
- ✅ **Header protection removal works correctly** - Unmasked PN = 0x8AAB2E (9,087,790)
- ✅ **Sample extraction fixed** - Always extracts from offset 4 regardless of guessed PN length
- ❌ **AEAD decryption still fails with `error.AuthenticationFailed`**
- ❌ Connection never added to `accepted` list
- ❌ Client times out after 5 seconds

### Root Cause
**AEAD decrypt authentication failure** - Header protection is now working, but AES-128-GCM decryption fails. Possible causes:
1. Initial keys are incorrect (wrong DCID, wrong salt, wrong HKDF)
2. Nonce derivation is incorrect
3. AAD (Additional Authenticated Data) construction is incorrect
4. The actual PN value is wrong (should be 0 or 1 for first packet, not 9,087,790)

### Evidence from Debug Logs
```
DEBUG: === processIncomingDatagram #1 called with 1280 bytes ===
DEBUG: Processing Initial packet from peer
DEBUG: Initial packet: dcid_len=10, scid_len=0
DEBUG: Server: Deriving Initial keys with dcid (len=10)=
DEBUG: DCID from packet (len=10)=
DEBUG: AEAD decrypt failed (auto-sample): error.AuthenticationFailed (pn=222)
DEBUG: AEAD decrypt failed (auto-sample): error.AuthenticationFailed (pn=56916)
DEBUG: AEAD decrypt failed (auto-sample): error.AuthenticationFailed (pn=14570728)
```

**Key Observation**: Packet numbers are garbage (222, 56916, 14570728) when they should be 0 or 1 for first Initial packets. This indicates header protection removal is failing.

### Likely Causes (Priority Order)

1. **Sample Offset Calculation Error** (MOST LIKELY)
   - RFC 9001: Sample starts 4 bytes after packet number field start
   - Current code (crypto_quic.zig:478-482): `sample_offset = if (pn_len >= 4) 0 else (4 - pn_len)`
   - This might be incorrect for how packet number field is positioned in the buffer

2. **Header Protection Key Derivation**
   - Check if HP key is being derived correctly from Initial secret
   - Verify HKDF-Expand-Label implementation in `src/quic/keyschedule.zig`

3. **AES-128 ECB Encryption of Sample**
   - Verify `unmaskLongHeaderAndPn` uses correct AES mode
   - Check if sample is being encrypted correctly before XOR with header bytes

### Files Requiring Investigation

**Primary**:
- `src/quic/crypto_quic.zig` lines 458-524: `unprotectInitialAutoSample()`
  - Line 478-482: Sample offset calculation
  - Line 496: `headerUnprotect()` call
  - Line 520: AEAD decryption

- `src/quic/crypto_quic.zig` lines 526-570: `unmaskLongHeaderAndPn()`
  - Line 540-541: AES-128 encryption of sample
  - Line 555-556: XOR mask application

**Secondary**:
- `src/quic/keyschedule.zig`: HKDF-Expand-Label for HP key derivation
- `src/quic/packet.zig`: Initial key derivation with `initialAeadKeys()`

### Next Steps for Debugging

1. **Add Detailed Crypto Logging**:
   ```zig
   // In unprotectInitialAutoSample after sample extraction
   logger.debug("Sample (16 bytes): ", .{});
   for (sample16) |b| logger.debug("{X:0>2} ", .{b});

   // After AES encryption in unmaskLongHeaderAndPn
   logger.debug("Mask (first 5 bytes): ", .{});
   for (out_block[0..5]) |b| logger.debug("{X:0>2} ", .{b});

   // Before and after XOR
   logger.debug("PN before unmask: ", .{});
   for (pn_bytes) |b| logger.debug("{X:0>2} ", .{b});
   logger.debug("PN after unmask: ", .{});
   ```

2. **Compare with Reference Implementation**:
   - Check quic-go's header protection: `forks/quic-go/internal/wire/header_protection.go`
   - Check aioquic's implementation: `forks/aioquic/src/aioquic/quic/packet.py`

3. **Test with Known Test Vectors**:
   - Use test vectors from RFC 9001 Appendix A
   - Verify sample extraction, mask generation, and XOR operations step-by-step

4. **Wireshark Packet Capture**:
   ```bash
   sudo tcpdump -i lo -w /tmp/quic-test.pcap udp port 4433 &
   bash test-with-go-client-debug.sh
   wireshark /tmp/quic-test.pcap
   ```
   - Inspect actual packet bytes from client
   - Compare with what server logs show

### Recommended Fix Strategy

1. Instrument the header protection code with detailed hex dumps
2. Capture a single packet from go client with Wireshark
3. Manually verify sample extraction matches RFC 9001 spec
4. Cross-reference with quic-go implementation
5. Fix the sample offset or mask calculation
6. Rebuild and retest

### Test Script
```bash
# After adding logging and rebuilding
rm /tmp/go-client-debug.log
bash test-with-go-client-debug.sh
grep -E "Sample|Mask|PN before|PN after" /tmp/go-client-debug.log | head -40
```

---

## Summary

**Progress**:
- ✅ Event loop fixed
- ✅ Key caching implemented
- ✅ RETRY cascade eliminated
- ⚠️ **Packet reception working** - Server receives and processes UDP packets
- ❌ **Decryption failing** - Header unprotection produces invalid PNs

**Current Blocker**: Cryptographic protocol bug in header protection removal (RFC 9001 §5.4)

**Next Action**: Add detailed logging to `unprotectInitialAutoSample()` and `unmaskLongHeaderAndPn()` to identify exact point of failure in header protection removal.

---

**Last Updated**: October 30, 2025 15:21
**Status**: Ready for cryptographic debugging
