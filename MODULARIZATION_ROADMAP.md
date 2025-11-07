# QUIC Library Modularization Roadmap

## Overview

This document identifies additional areas of the QUIC library that can be modularized and tested independently by RFC section. The goal is to continue breaking down large files into focused, RFC-aligned modules for better testability, maintainability, and spec compliance.

## Current Status

### ✅ Already Modularized (Phase 1-5)

**Connection Modules (12 files, 747 lines):**
- `connection/types.zig` (70 lines) - RFC 9000 §2-5
- `connection/crypto_buffer.zig` (165 lines) - RFC 9000 §4.9.2, RFC 9001 §4
- `connection/packet_number.zig` (137 lines) - RFC 9000 §12.3, §13.2, Appendix A.3
- `connection/ack.zig` (24 lines) - RFC 9000 §13.2, §19.3, RFC 3168
- `connection/stream.zig` (85 lines) - RFC 9000 §2-4, §19.8
- `connection/connection_id.zig` (47 lines) - RFC 9000 §5.1-5.3, §10.3, §19.15
- `connection/handshake.zig` (29 lines) - RFC 9001 §4, §8.2
- `connection/path.zig` (16 lines) - RFC 9000 §9, §19.17-19.18
- `connection/amplification.zig` (46 lines) - RFC 9000 §8.1
- `connection/pmtud.zig` (29 lines) - RFC 9000 §14.2-14.4, RFC 8899
- `connection/limits.zig` (26 lines) - RFC 9001 §6.6
- `connection/connection.zig` (73 lines) - Module coordinator

**Endpoint Modules (9 files, 497 lines):**
- `endpoint/types.zig` (94 lines) - RFC 9000 §5.1
- `endpoint/timer.zig` (119 lines) - RFC 9002 §6.2
- `endpoint/lookup.zig` (49 lines) - RFC 9000 §5.1-5.2
- `endpoint/io.zig` (56 lines) - RFC 9000 §13.3, RFC 3168
- `endpoint/client.zig` (23 lines) - RFC 9000 §7
- `endpoint/server.zig` (25 lines) - RFC 9000 §7, §8.1
- `endpoint/incoming.zig` (28 lines) - RFC 9000 §12-17
- `endpoint/pto.zig` (34 lines) - RFC 9002 §6.2
- `endpoint/endpoint.zig` (69 lines) - Module coordinator

### 📦 Existing Modules (Not Yet Modularized)

**Current Files:**
- `frame.zig` (636 lines) - Frame encoding/decoding
- `packet.zig` (1060 lines) - Packet encoding/decoding
- `recovery.zig` (463 lines) - RTT, loss detection, congestion control
- `transport_params.zig` (299 lines) - Transport parameters
- `varint.zig` (259 lines) - Variable-length integers ✅ (good size)
- `crypto_quic.zig` (654 lines) - QUIC-specific crypto operations

**Monolithic Files:**
- `conn.zig` (3449 lines) - Connection struct and methods
- `endpoint.zig` (3728 lines) - Endpoint struct and methods

---

## Phase 6: Frame Module Refactoring ✅ COMPLETED

**Target:** `frame.zig` (636 lines) → 10 focused modules (~50-120 lines each)

### Completed Structure: `src/quic/frame/*`

| Module | RFC Sections | Lines Est. | Purpose |
|--------|--------------|------------|---------|
| `frame/types.zig` | RFC 9000 §19 | 80 | Frame type enum, common types (AckRange, EcnCounts) |
| `frame/flow_control.zig` | RFC 9000 §4, §19.10-19.14 | 100 | MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, *_BLOCKED frames |
| `frame/stream.zig` | RFC 9000 §19.8 | 90 | STREAM frame encoding/decoding with offset/FIN |
| `frame/crypto.zig` | RFC 9000 §19.6 | 60 | CRYPTO frame for handshake data |
| `frame/connection_mgmt.zig` | RFC 9000 §19.15-19.16, §19.19 | 100 | NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, CONNECTION_CLOSE |
| `frame/path.zig` | RFC 9000 §19.17-19.18 | 70 | PATH_CHALLENGE, PATH_RESPONSE |
| `frame/ack.zig` | RFC 9000 §19.3, RFC 3168 | 120 | ACK, ACK_ECN with range encoding/decoding |
| `frame/misc.zig` | RFC 9000 §19.1-19.2, §19.7, §19.20 | 80 | PADDING, PING, NEW_TOKEN, HANDSHAKE_DONE |
| `frame/datagram.zig` | RFC 9221 | 60 | DATAGRAM frame (extension) |

**Benefits:**
- Test individual frame types in isolation
- Easy to verify against RFC frame format specs
- Simpler to add new frame types (QUIC extensions)
- Clear separation of concerns

**RFC Alignment:**
Each module maps directly to RFC 9000 §19 subsections, making spec compliance validation straightforward.

---

## Phase 7: Packet Module Refactoring ✅ COMPLETED

**Target:** `packet.zig` (1060 lines) → Hybrid modular structure

### Completed Structure: `src/quic/packet/*`

| Module | RFC Sections | Lines | Purpose |
|--------|--------------|-------|---------|
| `packet/types.zig` | RFC 9000 §17 | 56 | Common types (PacketNumber, LongHeaderType, Decoded* results, QUIC versions) |
| `packet/header.zig` | RFC 9000 §17.2-17.3 | 114 | LongHeader and ShortHeader structures for test/diagnostic use |
| `packet/packet.zig` | RFC 9000 §17, RFC 9001 §5 | 96 | Coordinator module: re-exports types, headers, and legacy packet functions |

**Implementation Approach:**
- **Hybrid Strategy**: Established modular architecture while maintaining API compatibility
- **Coordinator Pattern**: packet/packet.zig imports new modules (types, header) and re-exports legacy functions
- **Future Path**: Specialized modules (initial.zig, handshake.zig, one_rtt.zig, retry.zig, version_neg.zig, protection.zig) can be incrementally extracted in future phases

**Benefits:**
- Modular structure without breaking existing code
- Clear separation of types and header helpers
- RFC-aligned organization
- Established foundation for future packet module extraction

**RFC Alignment:**
Maps to RFC 9000 §17 (Packet Formats) and RFC 9001 §5.4 (Header Protection).

---

## Phase 8: Recovery Module Refactoring

**Target:** `recovery.zig` (463 lines) → 4-5 focused modules (~90-120 lines each)

### Proposed Structure: `src/quic/recovery/*`

| Module | RFC Sections | Lines Est. | Purpose |
|--------|--------------|------------|---------|
| `recovery/types.zig` | RFC 9002 §2 | 60 | Common types (CcState, SentPacket, AckFrame) |
| `recovery/rtt.zig` | RFC 9002 §5 | 120 | RTT estimation (RttState, onAck, computePto) |
| `recovery/loss_detection.zig` | RFC 9002 §6 | 150 | Loss detection algorithm, PTO computation |
| `recovery/congestion.zig` | RFC 9002 §7 | 100 | Common congestion control interface |
| `recovery/newreno.zig` | RFC 9002 §7.3, Appendix B.1 | 100 | NewReno congestion controller |
| `recovery/cubic.zig` | RFC 9002 Appendix B.2 | 120 | CUBIC congestion controller |

**Benefits:**
- Test RTT estimation independently
- Test congestion controllers in isolation
- Easy to add new congestion control algorithms
- Clear RFC 9002 section alignment

**RFC Alignment:**
Direct mapping to RFC 9002 sections (RTT, Loss Detection, Congestion Control).

---

## Phase 9: Connection Flow Control Extraction

**Target:** Extract flow control logic from `conn.zig` (currently embedded in 3449-line file)

### Proposed Structure: `src/quic/connection/flow_control.zig`

| Function | RFC Sections | Purpose |
|----------|--------------|---------|
| `checkConnectionFlowControl()` | RFC 9000 §4.1 | Connection-level flow control limits |
| `checkStreamFlowControl()` | RFC 9000 §4.2 | Stream-level flow control limits |
| `updateMaxData()` | RFC 9000 §4.1, §19.10 | Update connection-level receive window |
| `updateMaxStreamData()` | RFC 9000 §4.2, §19.11 | Update stream-level receive window |
| `checkStreamLimits()` | RFC 9000 §4.6 | Check MAX_STREAMS limits |
| `generateFlowControlFrames()` | RFC 9000 §19.10-19.14 | Generate MAX_* frames when needed |

**Benefits:**
- Test flow control independently
- Clearer RFC 9000 §4 compliance
- Easier to debug flow control issues

**Estimated Size:** ~200 lines

---

## Phase 10: Version Negotiation Module

**Target:** Extract version negotiation from `conn.zig` and `packet.zig`

### Proposed Structure: `src/quic/version.zig`

| Function | RFC Sections | Purpose |
|----------|--------------|---------|
| `parseVersion()` | RFC 9000 §6 | Parse version from packet |
| `isSupported()` | RFC 9000 §6.1 | Check if version is supported |
| `generateVersionNegotiation()` | RFC 9000 §6.2, §17.2.1 | Generate Version Negotiation packet |
| `validateVersionNegotiation()` | RFC 9000 §6.2 | Validate received VN packet |
| `getVersionSalt()` | RFC 9001 §5.2 | Get Initial salt for version |

**Benefits:**
- Test version negotiation independently
- Support QUIC v2 (RFC 9369) easily
- Clear version compatibility matrix

**Estimated Size:** ~150 lines

---

## Phase 11: Error Handling Module

**Target:** Extract error handling from `conn.zig`

### Proposed Structure: `src/quic/connection/error.zig`

| Function | RFC Sections | Purpose |
|----------|--------------|---------|
| `ErrorCode` enum | RFC 9000 §20 | All QUIC error codes |
| `generateConnectionClose()` | RFC 9000 §10.2, §19.19 | Generate CONNECTION_CLOSE frame |
| `handleConnectionClose()` | RFC 9000 §10.2 | Process CONNECTION_CLOSE |
| `enterDraining()` | RFC 9000 §10.2.1 | Enter draining state |
| `immediateClose()` | RFC 9000 §10.2.3 | Immediate close without draining |

**Benefits:**
- Test error handling independently
- Clear error code definitions (RFC 9000 §20)
- Easier to audit connection closure logic

**Estimated Size:** ~180 lines

---

## Phase 12: Idle Timeout Module

**Target:** Extract idle timeout logic from `conn.zig` and `endpoint.zig`

### Proposed Structure: `src/quic/connection/idle.zig`

| Function | RFC Sections | Purpose |
|----------|--------------|---------|
| `IdleTimer` struct | RFC 9000 §10.1 | Idle timeout state |
| `update()` | RFC 9000 §10.1.1 | Update on packet sent/received |
| `isExpired()` | RFC 9000 §10.1.2 | Check if idle timeout expired |
| `negotiateTimeout()` | RFC 9000 §10.1, §18.2 | Negotiate idle_timeout from transport params |

**Benefits:**
- Test idle timeout independently
- Clear timeout semantics
- Easy to tune timeout behavior

**Estimated Size:** ~100 lines

---

## Phase 13: Crypto/Key Management Refactoring

**Target:** `crypto_quic.zig` (654 lines) → 3-4 focused modules

### Proposed Structure: `src/quic/crypto/*`

| Module | RFC Sections | Lines Est. | Purpose |
|--------|--------------|------------|---------|
| `crypto/keys.zig` | RFC 9001 §5 | 180 | Key derivation (Initial, Handshake, 1-RTT) |
| `crypto/aead.zig` | RFC 9001 §5.3 | 200 | AEAD encryption/decryption |
| `crypto/header_protection.zig` | RFC 9001 §5.4 | 150 | Header protection (sample, mask, apply) |
| `crypto/key_update.zig` | RFC 9001 §6 | 150 | Key update mechanism |

**Benefits:**
- Test crypto operations independently
- Easier to audit TLS 1.3 integration
- Clear RFC 9001 section mapping

---

## Phase 14: Transport Parameters Refactoring

**Target:** `transport_params.zig` (299 lines) → Keep as-is or split by category

### Potential Split (Optional):

| Module | RFC Sections | Purpose |
|--------|--------------|---------|
| `transport_params/types.zig` | RFC 9000 §18 | Parameter IDs and types |
| `transport_params/codec.zig` | RFC 9000 §18 | Encoding/decoding |
| `transport_params/validation.zig` | RFC 9000 §7.4 | Parameter validation rules |

**Status:** 299 lines is reasonable, splitting is optional.

---

## Implementation Priority

### High Priority (Next Phase)
1. **Phase 6: Frame Refactoring** - High impact, clear RFC sections
2. **Phase 7: Packet Refactoring** - High complexity area, good testability gains

### Medium Priority
3. **Phase 8: Recovery Refactoring** - Already reasonably sized, but could improve
4. **Phase 9: Flow Control Extraction** - Important for RFC 9000 §4 compliance

### Lower Priority (Future Work)
5. **Phase 10: Version Negotiation** - Smaller, less urgent
6. **Phase 11: Error Handling** - Good for clarity, not urgent
7. **Phase 12: Idle Timeout** - Nice to have
8. **Phase 13: Crypto Refactoring** - Complex, requires careful planning
9. **Phase 14: Transport Params** - Optional, already reasonable size

---

## Testing Strategy

For each new module:

1. **Unit Tests** - Test the module in isolation
   - RFC compliance test vectors
   - Edge cases and boundary conditions
   - Error handling

2. **Integration Tests** - Test module interaction
   - Connection-level tests using new modules
   - Endpoint-level tests
   - Interop tests with other QUIC implementations

3. **RFC Compliance** - Verify against specs
   - Use `spec-compliance-validator` agent
   - Cross-reference with `@forks/quiche/` and `@forks/boringssl/`
   - Document RFC section coverage

---

## Benefits of Continued Modularization

### Code Quality
- **Smaller files**: Easier to understand and review (target: <200 lines per module)
- **Focused responsibility**: Each module does one thing well
- **Clear RFC alignment**: Easy to verify spec compliance

### Testing
- **Unit testability**: Test modules in isolation
- **Faster test cycles**: Run relevant tests only
- **Better coverage**: Easier to achieve complete RFC section coverage

### Maintenance
- **Easier debugging**: Find bugs in focused modules
- **Simpler changes**: Modifications localized to relevant modules
- **Clear ownership**: Each module maps to specific RFC sections

### Development
- **Parallel work**: Multiple developers can work on different modules
- **Easier onboarding**: New developers can understand focused modules
- **Extension support**: Easy to add QUIC extensions as new modules

---

## Metrics

### Current State
- **Total QUIC code**: ~10,000 lines
- **Modularized**: 1,244 lines (21 modules, avg 59 lines)
- **Not modularized**: ~8,756 lines (large files)

### Target State (After Phases 6-14)
- **Estimated modules**: 60-70 modules
- **Average module size**: 80-150 lines
- **Large files remaining**: conn.zig, endpoint.zig (main struct implementations)

### Modularization Progress
- **Phase 1-5**: ✅ 21 modules created (connection/*, endpoint/*)
- **Phase 6**: ✅ 10 frame modules created (types, misc, crypto, stream, ack, path, connection_mgmt, flow_control, datagram, frame coordinator)
- **Phase 7**: ✅ 3 packet modules created (types, header, packet coordinator with hybrid approach)
- **Phase 8**: 📋 6 recovery modules planned
- **Phase 9-14**: 📋 Additional focused modules

**Total Completed**: 34 modules (~2,875 lines modularized, avg 85 lines per module)

---

## Next Steps

1. **Review this roadmap** with stakeholders
2. **Prioritize phases** based on current development needs
3. **Start with Phase 6 (Frame refactoring)** - high impact, clear RFC sections
4. **Establish testing strategy** for each new module
5. **Update CLAUDE.md** as new modules are created
6. **Update agent configurations** with new module mappings

---

**Document Status:** Draft
**Last Updated:** 2025-11-07
**Related Docs:** `MIGRATION_TO_MODULAR_API.md`, `REFACTORING_STATUS.md`, `CLAUDE.md`
