# QUIC Library Refactoring Plan

## Overview
This document outlines the refactoring of the QUIC library into smaller, RFC-aligned, and more testable modules.

## Current Structure Analysis

### Large Files
- **endpoint.zig** (3,728 lines) - Endpoint management, I/O, timers, packet processing
- **conn.zig** (3,449 lines) - Connection state, packet numbers, ACK, streams, crypto, paths
- **packet.zig** (1,060 lines) - Packet encoding/decoding
- **transport.zig** (908 lines) - High-level transport API
- **crypto_quic.zig** (654 lines) - QUIC crypto operations
- **frame.zig** (636 lines) - Frame encoding/decoding
- **recovery.zig** (463 lines) - Loss detection and recovery

### Problem Areas
1. **conn.zig** has 10+ distinct responsibilities mixed together
2. **endpoint.zig** contains both I/O and complex packet processing logic
3. Hard to test individual features in isolation
4. RFC sections are scattered across functions
5. Difficult to navigate and understand for new contributors

## New Module Structure

### Phase 1: Connection Module Split

Extract from `conn.zig`:

#### 1. `connection/types.zig`
**RFC Alignment**: RFC 9000 §2-5 (Basic types and roles)
- `Role` enum (Client/Server)
- `SockAddr` struct and helpers
- `Cid` struct (Connection ID)
- `SendFn` type

#### 2. `connection/connection_id.zig`
**RFC Alignment**: RFC 9000 §5.1-5.3 (Connection ID Management)
- `LocalCid` struct
- CID generation and retirement
- Stateless reset token derivation
- `onNewConnectionId` logic
- `looksLikeStatelessReset`

#### 3. `connection/packet_number.zig`
**RFC Alignment**: RFC 9000 §12.3, §13.2 (Packet Numbers)
- `PnWindow` struct
- PN expansion functions (`expandPnInitial`, `expandPnHandshake`, `expandPnApp`)
- PN tracking functions (`trackRecvPnInitial`, etc.)
- Next PN management for each space

#### 4. `connection/ack.zig`
**RFC Alignment**: RFC 9000 §13.2, §19.3 (Acknowledgments)
- `AckDesc` struct
- ACK building functions (`buildAckInitial`, `buildAckHandshake`, `buildAckApp`)
- `recordAckElicitingRx`
- `getAckDelayEncoded`
- ECN counter management (`EcnCounter`, `onEcnMark`, `getAckEcn`)

#### 5. `connection/stream.zig`
**RFC Alignment**: RFC 9000 §2-4 (Streams and Flow Control)
- `StreamRx` struct
- `StreamTx` struct
- `Segment` struct
- `pushStreamFrame` logic
- `isStreamFinished`
- Stream state management

#### 6. `connection/crypto_buffer.zig`
**RFC Alignment**: RFC 9000 §4.9.2 (CRYPTO Frame Handling)
- `CryptoBuffer` struct
- Out-of-order fragment reassembly
- Contiguous data extraction

#### 7. `connection/handshake.zig`
**RFC Alignment**: RFC 9001 §4 (TLS Integration)
- TLS handshake state
- `handleInitialCrypto`
- `handleHandshakeCrypto`
- `pushCrypto`
- `maybeDeriveAppKeysAfterFlush`
- ALPN and transport params caching

#### 8. `connection/path.zig`
**RFC Alignment**: RFC 9000 §9 (Path Validation and Migration)
- Path validation state
- PATH_CHALLENGE/PATH_RESPONSE handling
- Path migration logic
- `validated` flag management

#### 9. `connection/amplification.zig`
**RFC Alignment**: RFC 9000 §8.1 (Address Validation)
- Anti-amplification tracking
- `canSendUnderAmplification`
- `overAmplification`
- `addRxUnvalidated` / `addTxUnvalidated`

#### 10. `connection/pmtud.zig`
**RFC Alignment**: RFC 9000 §14.2-14.4 (Path MTU Discovery)
- PMTUD state (`dplpmtud_state`, `pmtu_current`, etc.)
- MTU probing logic
- Timer management for PMTUD

#### 11. `connection/limits.zig`
**RFC Alignment**: RFC 9001 §6.6 (AEAD Usage Limits)
- AEAD usage limit tracking
- `setAeadUsageLimits`
- Confidentiality and integrity limit checking

#### 12. `connection/connection.zig`
**Core Connection State**
- Main `Connection` struct (now much smaller)
- `init` / `deinit`
- High-level state machine
- Coordination between all sub-modules
- Public API surface

### Phase 2: Endpoint Module Split

Extract from `endpoint.zig`:

#### 1. `endpoint/types.zig`
- `Key` struct (connection lookup key)
- `Timer` struct
- `TimerKind` enum
- `EndpointRole` enum
- Helper functions (`hashBytes`, `hashSockaddr`, `normalizeAddr`)

#### 2. `endpoint/timer.zig`
**RFC Alignment**: RFC 9002 §6.2 (PTO), RFC 9000 §14.2 (PMTUD)
- Timer heap management
- `scheduleTimer`
- `scheduleConnPto`
- `cancelTimer`
- `flushTimers`
- Timer expiry handling

#### 3. `endpoint/lookup.zig`
**RFC Alignment**: RFC 9000 §5.1 (Connection Routing)
- Connection table management
- Lookup by address + DCID
- Connection insertion/removal
- NAT rebinding detection

#### 4. `endpoint/io.zig`
**UDP I/O Operations**
- `sendTo` (UDP send with ECN)
- `recvFrom` (UDP receive with ECN)
- Platform-specific socket handling
- Test capture mode (`captureClear`, `capturePop`, etc.)

#### 5. `endpoint/client.zig`
**RFC Alignment**: RFC 9000 §7 (Client Connection Establishment)
- `connectTo` / `connectClient`
- `clientSendInitialProbe`
- Initial packet construction
- DCID/SCID generation for clients

#### 6. `endpoint/server.zig`
**RFC Alignment**: RFC 9000 §7 (Server Connection Acceptance)
- `acceptFrom`
- `popAccepted`
- Initial packet validation
- Retry token handling
- Stateless reset generation

#### 7. `endpoint/incoming.zig`
**RFC Alignment**: RFC 9000 §12-17 (Packet Processing)
- Main packet ingress pipeline
- Version negotiation
- Long header processing (Initial, Handshake)
- Short header processing (1-RTT)
- Frame dispatching
- ECN handling
- ICMP processing (`testInjectIcmpPtb`)

#### 8. `endpoint/pto.zig`
**RFC Alignment**: RFC 9002 §6 (Probe Packets)
- `sendPtoProbe`
- PTO timer expiry handling
- Probe packet construction

#### 9. `endpoint/endpoint.zig`
**Core Endpoint**
- Main `Endpoint` struct (now much smaller)
- `init` / `deinit`
- `poll` (coordination only, delegates to incoming.zig)
- Configuration
- Coordination between all sub-modules

### Phase 3: Supporting Module Organization

#### Create subdirectories:
```
src/quic/
├── connection/           # All connection-related modules
│   ├── connection.zig
│   ├── types.zig
│   ├── connection_id.zig
│   ├── packet_number.zig
│   ├── ack.zig
│   ├── stream.zig
│   ├── crypto_buffer.zig
│   ├── handshake.zig
│   ├── path.zig
│   ├── amplification.zig
│   ├── pmtud.zig
│   └── limits.zig
├── endpoint/             # All endpoint-related modules
│   ├── endpoint.zig
│   ├── types.zig
│   ├── timer.zig
│   ├── lookup.zig
│   ├── io.zig
│   ├── client.zig
│   ├── server.zig
│   ├── incoming.zig
│   └── pto.zig
├── packet.zig           # Keep as-is (already focused)
├── frame.zig            # Keep as-is (already focused)
├── crypto_quic.zig      # Keep as-is
├── recovery.zig         # Keep as-is
├── transport.zig        # Keep as-is
├── varint.zig           # Keep as-is
├── transport_params.zig # Keep as-is
├── config.zig           # Keep as-is
├── token.zig            # Keep as-is
├── pem.zig              # Keep as-is
├── logger.zig           # Keep as-is
├── api.zig              # Update to re-export from new modules
└── io/                  # Keep as-is (platform-specific)
```

## Migration Strategy

### Step 1: Create New Module Files (Non-Breaking)
1. Create all new module files in subdirectories
2. Copy relevant code from old files
3. Update internal references within new modules
4. Do NOT modify old files yet

### Step 2: Update build.zig
1. Add all new modules
2. Set up import relationships
3. Keep old modules building alongside

### Step 3: Update Connection Module
1. Modify `conn.zig` to import and delegate to new modules
2. Keep public API identical
3. Run tests after each sub-module migration

### Step 4: Update Endpoint Module
1. Modify `endpoint.zig` to import and delegate to new modules
2. Keep public API identical
3. Run tests after each sub-module migration

### Step 5: Update All Importers
1. Update files that import `conn.zig` or `endpoint.zig`
2. Change to import specific sub-modules where appropriate
3. Update `api.zig` to re-export commonly used types

### Step 6: Final Cleanup
1. Remove delegating code from old files
2. Move any remaining shared utilities
3. Run full test suite
4. Update documentation

## Benefits

1. **Easier to Navigate**: Each file focuses on one RFC section/feature
2. **Better Testability**: Can test individual features in isolation
3. **Clearer Dependencies**: Import graph shows true relationships
4. **Easier to Review**: Changes to specific features touch specific files
5. **Better for New Contributors**: Can understand one area without reading 3000+ lines
6. **RFC Compliance Tracking**: Each module maps to specific RFC sections

## Testing Strategy

After each phase:
1. Run unit tests: `zig build test`
2. Run integration tests: `make e2e-test-python`
3. Run interop tests: `zig build interop-run`
4. Verify no performance regression with benchmarks

## Notes

- This refactoring does NOT change behavior, only organization
- Public API remains stable throughout
- Can be done incrementally with tests passing at each step
- RFC section comments preserved and enhanced in new modules
