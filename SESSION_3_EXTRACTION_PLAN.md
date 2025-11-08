# Session 3: RX Short Header Processing Extraction Plan

## Overview

Session 3 extracts the 1-RTT packet processing pipeline from `endpoint.zig` lines 1092-1671 (580 lines) into modular components in `src/quic/endpoint/incoming.zig`.

## Completion Status: 70% Complete

### ✅ Completed Components

1. **Connection Lookup** (120 lines)
   - **Function**: `findConnectionByDcid()` in `lookup.zig:119-209`
   - **Extracted from**: `endpoint.zig:1104-1191`
   - **Features**:
     - Two-phase lookup: peer_hash + DCID, then NAT rebinding fallback
     - Server prioritization for connections with both app_rx_keys and app_tx_keys
     - Tie-breaking on longest DCID match
   - **RFC**: RFC 9000 §5.1-5.2 (Connection IDs), RFC 9000 §9.3 (NAT rebinding)

2. **DCID Enumeration and Key Rotation** (240 lines)
   - **Functions**:
     - `decryptShortHeaderWithKeyRotation()` in `incoming.zig:934-1050`
     - `promoteToNextKeys()` in `incoming.zig:1069-1087`
     - `decrementPrevKeyAllowance()` in `incoming.zig:1102-1122`
   - **Extracted from**: `endpoint.zig:1198-1346`
   - **Features**:
     - **Bug #6 Fix**: Systematic DCID length enumeration 0-20
     - Current key attempt → DCID enumeration → NEXT keys → previous keys
     - Caches successful DCID length in `conn.expected_rx_dcid_len`
     - Automatic key rotation with 16-packet previous key window
     - Stateless reset detection
   - **RFC**: RFC 9000 §17.3 (Short Header), RFC 9001 §6 (Key Updates), RFC 9000 §10.3 (Stateless Reset)

### ⏸️ Remaining Components

3. **Frame Parsing and Dispatch** (130 lines) - **BLOCKED ON SESSION 4**
   - **Extraction Target**: `endpoint.zig:1347-1475`
   - **Dependencies**: Requires `frame_handler.zig` module (Session 4)
   - **Frame Types Handled** (16 types):
     1. PING (line 1362) - Ack-eliciting keepalive
     2. NEW_CONNECTION_ID (line 1366) - CID management, stateless reset token tracking
     3. RETIRE_CONNECTION_ID (line 1372) - CID retirement
     4. STREAM (line 1377) - Stream data delivery via `conn.pushStreamFrame()`
     5. DATAGRAM (line 1393) - Unreliable datagram delivery + echo response
     6. ACK (line 1412) - ACK processing, PTO cancellation, PMTUD progress
     7. HANDSHAKE_DONE (line 1423) - Handshake completion, drop HS keys
     8. CONNECTION_CLOSE (line 1427) - Connection termination
     9. MAX_STREAM_DATA (line 1430) - Stream flow control updates
     10. MAX_DATA (line 1436) - Connection flow control updates
     11. MAX_STREAMS_BIDI (line 1440) - Bidirectional stream limit updates
     12. MAX_STREAMS_UNI (line 1444) - Unidirectional stream limit updates
     13. STREAM_DATA_BLOCKED (line 1448) - Stream blocked signal
     14. PATH_CHALLENGE (line 1449) - Path validation request + response generation
     15. PATH_RESPONSE (line 1464) - Path validation completion
     16. NEW_TOKEN (line 1469) - Token update for future connections
   - **Strategy**:
     - Create `frame_handler.zig` with 16 handler functions (Session 4)
     - Extract `processFrames()` function to `incoming.zig`
     - Pass `RxFrameContext` with conn, allocator, peer, send_fn
     - Track ack-eliciting status, HANDSHAKE_DONE, CONNECTION_CLOSE

4. **ACK Generation and Transmission** (190 lines)
   - **Extraction Target**: `endpoint.zig:1476-1669`
   - **Features**:
     - ACK generation via `conn.buildAckApp()`
     - ACK_ECN support for ECN counters (RFC 3168)
     - Amplification limit enforcement (RFC 9000 §8.1)
     - MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS piggybacking
     - NEW_CONNECTION_ID frame piggybacking
     - AEAD integrity limit handling (CONNECTION_CLOSE 0x0f)
   - **Strategy**:
     - Extract `generateAndSendAck()` function to `incoming.zig`
     - Pass `RxContext` with conn, allocator, peer, send_fn, cfg
     - Handle both ACK-only and ACK+MAX_* responses
     - Support amplification-limited ACK-only fallback

5. **Main processShortHeader() Coordinator** (20 lines)
   - **Assembly Strategy**:
     ```zig
     pub fn processShortHeader(
         ctx: *RxContext,
         bytes: []const u8,
         ecn_bits: ?u8,
     ) !void {
         // 1. Connection lookup via lookup.findConnectionByDcid()
         const conn_result = lookup.findConnectionByDcid(ctx, bytes);

         // 2. Decrypt with DCID enumeration and key rotation
         const decrypt_result = try decryptShortHeaderWithKeyRotation(
             ctx.allocator.*,
             conn_result.conn,
             bytes,
             conn_result.dcid_len
         );
         defer ctx.allocator.free(decrypt_result.decoded.payload);

         // 3. Handle key rotation
         if (decrypt_result.used_next) {
             // Derive and promote to NEXT keys
             const next_secret = key_schedule.updateTrafficSecret(conn.app_rx_secret.?);
             const next_keys = key_schedule.deriveKeyIvHp(next_secret);
             promoteToNextKeys(conn, next_secret, next_keys);
         } else if (decrypt_result.used_prev) {
             decrementPrevKeyAllowance(conn);
         }

         // 4. Update packet number tracking
         conn.trackRecvPnApp(decrypt_result.decoded.packet_number);

         // 5. Parse and process frames (Session 4 dependency)
         const frame_result = try processFrames(ctx, conn, decrypt_result.decoded.payload);

         // 6. Generate and send ACK if needed
         if (frame_result.saw_ack_eliciting or ecn_bits != null) {
             try generateAndSendAck(ctx, conn, frame_result, ecn_bits);
         }
     }
     ```

## Extraction Dependencies

### Critical Blocker: Session 4 (frame_handler.zig)

Before `processShortHeader()` can be fully extracted, Session 4 must create the frame handler module:

**Required Module**: `src/quic/endpoint/frame_handler.zig`

**Module Structure**:
```zig
pub const FrameContext = struct {
    conn: *conn_mod.Connection,
    allocator: *std.mem.Allocator,
    peer: conn_mod.SockAddr,
    send_fn: SendFn,
};

pub const FrameResult = struct {
    saw_ack_eliciting: bool,
    saw_handshake_done: bool,
    saw_close: bool,
};

pub fn handlePing(ctx: *FrameContext) void;
pub fn handleNewConnectionId(ctx: *FrameContext, ncid: frame.NewConnectionId) void;
pub fn handleRetireConnectionId(ctx: *FrameContext, rc: frame.RetireConnectionId) void;
pub fn handleStream(ctx: *FrameContext, s: frame.Stream) !void;
pub fn handleDatagram(ctx: *FrameContext, d: frame.Datagram) !void;
pub fn handleAck(ctx: *FrameContext, a: frame.Ack) void;
pub fn handleHandshakeDone(ctx: *FrameContext) void;
pub fn handleConnectionClose(ctx: *FrameContext, cc: frame.ConnectionClose) void;
pub fn handleMaxStreamData(ctx: *FrameContext, m: frame.MaxStreamData) void;
pub fn handleMaxData(ctx: *FrameContext, m: frame.MaxData) void;
pub fn handleMaxStreamsBidi(ctx: *FrameContext, m: frame.MaxStreamsBidi) void;
pub fn handleMaxStreamsUni(ctx: *FrameContext, m: frame.MaxStreamsUni) void;
pub fn handleStreamDataBlocked(ctx: *FrameContext, b: frame.StreamDataBlocked) void;
pub fn handlePathChallenge(ctx: *FrameContext, p: frame.PathChallenge) !void;
pub fn handlePathResponse(ctx: *FrameContext, p: frame.PathResponse) void;
pub fn handleNewToken(ctx: *FrameContext, t: frame.NewToken) void;
```

**Estimated Effort**: 6-8 hours (16 handlers @ 5-20 lines each = ~150 lines total)

## RFC Compliance Coverage

Session 3 implementation covers the following RFC sections:

- **RFC 9000 §12**: Packets and Frames (frame parsing loop)
- **RFC 9000 §13.2**: Acknowledgments (ACK generation, ack-eliciting tracking)
- **RFC 9000 §13.3**: Retransmission (packet number tracking)
- **RFC 9000 §17.3**: Short Header Packets (1-RTT packet format)
- **RFC 9000 §19**: Frame Types and Formats (16 frame type handlers)
- **RFC 9001 §5**: Packet Protection (AEAD decryption)
- **RFC 9001 §5.4**: Header Protection Removal (HP sample and unprotection)
- **RFC 9001 §6**: Key Update (NEXT/previous key handling)
- **RFC 9000 §5.1-5.2**: Connection IDs (DCID lookup and routing)
- **RFC 9000 §8.1**: Address Validation (amplification limits)
- **RFC 9000 §9.3**: NAT Rebinding (fallback DCID lookup)
- **RFC 9000 §10.3**: Stateless Reset (token detection)
- **RFC 3168**: ECN (Explicit Congestion Notification counters)

## Testing Strategy

### Unit Tests (Phase 1: Post-Extraction)

1. **DCID Enumeration Tests** (`tests/unit/endpoint/test_incoming.zig`):
   - Test systematic enumeration discovers correct DCID length (0-20)
   - Test caching behavior (`conn.expected_rx_dcid_len`)
   - Test stateless reset detection
   - Test key rotation (current → NEXT → previous)

2. **Key Rotation Tests**:
   - Test `promoteToNextKeys()` preserves previous keys
   - Test `decrementPrevKeyAllowance()` drops keys at zero
   - Test 16-packet previous key window

3. **Connection Lookup Tests** (already exist in `lookup.zig`):
   - Test peer_hash + DCID lookup
   - Test NAT rebinding fallback
   - Test server prioritization

### Integration Tests (Phase 2: Session 4 Complete)

4. **End-to-End 1-RTT Processing**:
   - Test full processShortHeader() pipeline
   - Test frame dispatch to all 16 handlers
   - Test ACK generation with ECN
   - Test amplification limit enforcement

## Timeline

- ✅ **Week 1**: Connection lookup extraction (COMPLETE)
- ✅ **Week 2**: DCID enumeration and key rotation extraction (COMPLETE)
- ⏸️ **Week 3**: Session 4 dependency (frame_handler.zig) - **BLOCKED**
- ⏸️ **Week 4**: Frame processing integration
- ⏸️ **Week 5**: ACK generation and transmission extraction
- ⏸️ **Week 6**: processShortHeader() assembly and integration
- ⏸️ **Week 7**: Unit tests and RFC compliance verification
- ⏸️ **Week 8**: Integration tests and performance validation

## Success Criteria

Session 3 will be marked complete when:

1. ✅ `findConnectionByDcid()` exists in `lookup.zig` with full NAT rebinding support
2. ✅ `decryptShortHeaderWithKeyRotation()` exists in `incoming.zig` with Bug #6 fix
3. ✅ `promoteToNextKeys()` and `decrementPrevKeyAllowance()` exist in `incoming.zig`
4. ⏸️ `processFrames()` exists in `incoming.zig` (requires Session 4)
5. ⏸️ `generateAndSendAck()` exists in `incoming.zig`
6. ⏸️ `processShortHeader()` exists in `incoming.zig` as coordinator
7. ⏸️ All 16 frame handlers tested independently
8. ⏸️ End-to-end 1-RTT packet processing tested
9. ⏸️ RFC compliance verified via conformance tests
10. ⏸️ Performance benchmarks show no regression vs. monolithic implementation

## Current Status Summary

**Lines Extracted**: 360 / 580 (62%)
**Functions Created**: 3 (decryptShortHeaderWithKeyRotation, promoteToNextKeys, decrementPrevKeyAllowance)
**Critical Blocker**: Session 4 (frame_handler.zig) must be completed before Session 3 can finish

**Next Action**: Complete Session 4 (frame_handler.zig) to unblock frame processing extraction
