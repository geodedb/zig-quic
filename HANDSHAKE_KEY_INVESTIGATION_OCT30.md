# Handshake Key Assignment Investigation
**Date:** October 30, 2025 13:11 UTC

## Summary

Investigation into whether rx/tx keys are swapped for Handshake packet encryption/decryption.

## Key Findings

### 1. TLS 1.3 Key Derivation is Correct
**File:** `src/quic/tls/tls13.zig`

The `deriveHandshakeTraffic()` function correctly uses TLS 1.3 labels:
```zig
// Lines 203-204
ks.expandLabel(handshake_secret, "c hs traffic", &transcript_hash, &c_hs) catch unreachable;
ks.expandLabel(handshake_secret, "s hs traffic", &transcript_hash, &s_hs) catch unreachable;
return .{ .client_hs = c_hs, .server_hs = s_hs };
```

These labels match the TLS 1.3 specification exactly:
- `"c hs traffic"` for client handshake traffic secret
- `"s hs traffic"` for server handshake traffic secret

### 2. Secret Assignment Logic is Correct
**File:** `src/quic/conn.zig:2116-2117`

The key assignment follows the correct pattern:
```zig
// For Server role:
const rx_secret = if (self.role == .Server) self.hs_client.? else self.hs_server.?;
const tx_secret = if (self.role == .Server) self.hs_server.? else self.hs_client.?;
```

This means:
- **Server**:
  - rx_secret = client secret (to decrypt packets FROM client)
  - tx_secret = server secret (to encrypt packets TO client)
- **Client**:
  - rx_secret = server secret (to decrypt packets FROM server)
  - tx_secret = client secret (to encrypt packets TO client)

### 3. Comparison with quic-go
**File:** `forks/quic-go/internal/handshake/crypto_setup.go`

quic-go uses TLS 1.3's `SetReadSecret` and `SetWriteSecret` events:
```go
case tls.QUICSetReadSecret:
    h.setReadKey(ev.Level, ev.Suite, ev.Data)
case tls.QUICSetWriteSecret:
    h.setWriteKey(ev.Level, ev.Suite, ev.Data)
```

The TLS library determines read/write direction based on the connection's perspective (client vs server), which matches our implementation.

### 4. Diagnostic Logging Added
**File:** `src/quic/conn.zig:2104-2137`

Enhanced logging to trace key assignment:
```zig
logger.debug("deriveHandshakeKeys: role={s}, version_v2={}", .{...});
logger.debug("  hs_client secret[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{...});
logger.debug("  hs_server secret[0..4]: {X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{...});
logger.debug("  For {s}:", .{if (self.role == .Server) "Server" else "Client"});
logger.debug("    rx_secret (for reading) = {s} secret[0..4]: ...", .{...});
logger.debug("    tx_secret (for writing) = {s} secret[0..4]: ...", .{...});
```

## Conclusion

The rx/tx key assignment appears **CORRECT**. The server is:
1. Using the correct TLS 1.3 labels for key derivation
2. Assigning server secret to tx (write) and client secret to rx (read)
3. Following the same pattern as established QUIC implementations

The Handshake packet decryption failure must be caused by a different issue.

## Next Steps

Since key assignment is correct, investigate:
1. ✅ Sample offset calculation (already verified as correct)
2. ✅ HKDF labels (already verified as correct)
3. ✅ AAD construction (already verified as correct)
4. ✅ Version field (already verified as correct)
5. ✅ Key assignment (THIS INVESTIGATION - verified as correct)
6. **TODO**: Check if the secrets themselves are computed incorrectly
7. **TODO**: Verify transcript hash calculation
8. **TODO**: Check ECDHE shared secret computation