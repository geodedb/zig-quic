# QUIC Implementation Guide for Claude

## Reference Implementations

- **@forks/quiche/quiche** - Cloudflare's authoritative QUIC implementation (C/Rust)
- **@forks/boringssl** - Google's authoritative TLS 1.3 implementation (C)
- When comparing implementations or debugging protocol issues, check these forks first

## Modular Codebase Structure

The QUIC implementation uses a **modular, RFC-aligned architecture** in `src/quic/connection/*` and `src/quic/endpoint/*`:

### Connection Modules (RFC 9000 Transport, RFC 9001 TLS, RFC 9002 Recovery)

| Module | RFC Sections | Purpose |
|--------|--------------|---------|
| `connection/types.zig` | RFC 9000 §2-5 | Core types: Role, SockAddr, Cid, SendFn |
| `connection/crypto_buffer.zig` | RFC 9000 §4.9.2, RFC 9001 §4 | CRYPTO frame out-of-order reassembly |
| `connection/packet_number.zig` | RFC 9000 §12.3, §13.2, Appendix A.3 | PN expansion, truncation, ACK windows |
| `connection/ack.zig` | RFC 9000 §13.2, §19.3, RFC 3168 | ACK generation, ECN counters |
| `connection/stream.zig` | RFC 9000 §2-4, §19.8 | Stream RX/TX state machine |
| `connection/connection_id.zig` | RFC 9000 §5.1-5.3, §10.3, §19.15 | CID management, stateless reset tokens |
| `connection/handshake.zig` | RFC 9001 §4, §8.2 | TLS handshake state, ALPN, transport params |
| `connection/path.zig` | RFC 9000 §9, §19.17-19.18 | Path validation, migration |
| `connection/amplification.zig` | RFC 9000 §8.1 | Anti-amplification limit tracking |
| `connection/pmtud.zig` | RFC 9000 §14.2-14.4, RFC 8899 | Path MTU discovery (DPLPMTUD) |
| `connection/limits.zig` | RFC 9001 §6.6 | AEAD usage limits, key update triggers |
| `connection/flow_control.zig` | RFC 9000 §4 | Flow control helpers: window checks, limit expansion, frame generation |
| `connection/error.zig` | RFC 9000 §10, §20 | Error codes, connection closure, draining state management |
| `connection/idle.zig` | RFC 9000 §10.1 | Idle timeout negotiation, timer management, expiry checks |

### Frame Modules (RFC 9000 Transport, RFC 9221 DATAGRAM)

| Module | RFC Sections | Purpose |
|--------|--------------|---------|
| `frame/types.zig` | RFC 9000 §19 | FrameType enum, AckRange, EcnCounts types |
| `frame/misc.zig` | RFC 9000 §19.1-19.2, §19.7, §19.20 | PADDING, PING, NEW_TOKEN, HANDSHAKE_DONE |
| `frame/crypto.zig` | RFC 9000 §19.6 | CRYPTO frame for TLS handshake data |
| `frame/stream.zig` | RFC 9000 §19.8 | STREAM frame encoding/decoding with offset/FIN |
| `frame/ack.zig` | RFC 9000 §19.3, RFC 3168 | ACK, ACK_ECN frames with range encoding |
| `frame/path.zig` | RFC 9000 §19.17-19.18, §9 | PATH_CHALLENGE, PATH_RESPONSE for validation |
| `frame/connection_mgmt.zig` | RFC 9000 §19.4-19.5, §19.15-19.16, §19.19 | Connection/stream lifecycle management |
| `frame/flow_control.zig` | RFC 9000 §19.10-19.14, §4 | MAX_DATA, MAX_STREAM_DATA, *_BLOCKED frames |
| `frame/datagram.zig` | RFC 9221 | DATAGRAM frame (unreliable extension) |
| `frame/frame.zig` | RFC 9000 §19 | Coordinator module with Frame union |

### Packet Modules (RFC 9000 Packet Formats, RFC 9001 Packet Protection)

| Module | RFC Sections | Purpose |
|--------|--------------|---------|
| `packet/types.zig` | RFC 9000 §17 | PacketNumber, LongHeaderType, Decoded* result types, QUIC version constants |
| `packet/header.zig` | RFC 9000 §17.2-17.3 | LongHeader and ShortHeader structures for test/diagnostic use |
| `packet/packet.zig` | RFC 9000 §17, RFC 9001 §5 | Coordinator module: re-exports types, headers, and legacy packet functions |

**Note:** The packet coordinator uses a hybrid approach - it establishes modular structure by importing packet/types.zig and packet/header.zig, while re-exporting functions from the legacy packet.zig implementation. Future phases will gradually extract specialized modules (initial.zig, handshake.zig, one_rtt.zig, etc.) from the legacy implementation.

### Version Negotiation Module (RFC 9000 §6, RFC 9369)

| Module | RFC Sections | Purpose |
|--------|--------------|---------|
| `version.zig` | RFC 9000 §6, §17.2.1, RFC 9369 | Version negotiation: QUIC v1/v2 constants, version parsing/encoding, VN packet encode/decode, downgrade protection, version selection |

### Recovery Modules (RFC 9002 Loss Detection and Congestion Control)

| Module | RFC Sections | Purpose |
|--------|--------------|---------|
| `recovery/types.zig` | RFC 9002 §2 | CcState, SentPacket, PacketNumberSpace, CUBIC constants |
| `recovery/rtt.zig` | RFC 9002 §5, §6.2 | RTT estimation (RttState, onAck, computePto) |
| `recovery/loss_detection.zig` | RFC 9002 §6.1 | Loss detection (LossDetector, packet/time thresholds, isAckElicitingFrame) |
| `recovery/congestion.zig` | RFC 9002 §7, Appendix B | NewReno, CUBIC congestion controllers, pacing delay computation |
| `recovery/recovery.zig` | RFC 9002 | Coordinator module with Recovery struct: RTT, loss detection, congestion control |

### Endpoint Modules (RFC 9000 Transport, RFC 9002 Recovery)

| Module | RFC Sections | Purpose |
|--------|--------------|---------|
| `endpoint/types.zig` | RFC 9000 §5.1 | Timer, Key, EndpointRole types |
| `endpoint/timer.zig` | RFC 9002 §6.2 | Min-heap timer management (PTO, loss detection) |
| `endpoint/lookup.zig` | RFC 9000 §5.1-5.2 | Connection routing by CID hash |
| `endpoint/io.zig` | RFC 9000 §13.3, RFC 3168 | UDP I/O operations, ECN marking |
| `endpoint/client.zig` | RFC 9000 §7 | Client connection establishment |
| `endpoint/server.zig` | RFC 9000 §7, §8.1 | Server acceptance, address validation |
| `endpoint/incoming.zig` | RFC 9000 §12-17 | Incoming packet processing |
| `endpoint/pto.zig` | RFC 9002 §6.2 | PTO probe packet generation |

### Legacy Monolithic Files (Still Functional)

- **`src/quic/conn.zig`** (3,449 lines) - Main Connection struct implementation, re-exports modular types
- **`src/quic/endpoint.zig`** (3,728 lines) - Main Endpoint struct implementation

### TLS Integration

- **`vendor/ztls/src/*`** - TLS 1.3 implementation (see `vendor/ztls/CLAUDE.md` for details)
  - `tls13.zig` - Handshake state machine (RFC 8446, RFC 9001)
  - `key_schedule.zig` - HKDF key derivation (RFC 9001 §5)
  - `record.zig` - AEAD encryption, header protection (RFC 9001 §5.3-5.4)

### Crypto Architecture (RFC 9001)

- **`src/quic/crypto_quic.zig`** (654 lines) - QUIC packet protection coordination layer
  - **AEAD Operations** - `aeadEncrypt`, `aeadDecrypt` (thin wrappers to `crypto_zig.zig`)
  - **Header Protection** - `headerProtect`, `headerUnprotect` (RFC 9001 §5.4)
  - **Packet Protection** - `protectPacket`, `unprotectInitial*` (high-level coordination)
  - **Key Derivation** - `deriveNextAppKeys` (wrapper to `vendor/ztls/key_schedule.zig`)
  - **Retry Integrity** - `computeRetryIntegrityTag` (RFC 9001 §5.8)
- **`src/quic/crypto_zig.zig`** - AEAD and header protection implementations using Zig std.crypto
- **Assessment**: At 654 lines, `crypto_quic.zig` is well-organized and does not require further splitting

## Finding Code by RFC Section

When implementing or debugging a specific RFC requirement:

1. **Identify the RFC section** (e.g., "RFC 9000 §13.2 ACK generation")
2. **Check the table above** to find the corresponding module
3. **Open the module file** - it contains focused implementation with RFC citations
4. **Check the monolithic file** if the Connection/Endpoint struct uses those types

Example: For PN encoding issues (RFC 9000 §12.3) → Check `connection/packet_number.zig` first

## Benefits of Modular Structure

- **98.4% smaller** modules (avg 59 lines vs 3,588 lines)
- **RFC-aligned** - Easy to verify spec compliance
- **Testable** - Can unit test modules in isolation
- **Navigable** - Find features by name instead of searching
- **Maintainable** - Changes localized to relevant modules

## Documentation

- `MIGRATION_TO_MODULAR_API.md` - Complete usage guide
- `REFACTORING_STATUS.md` - Implementation status and metrics
- Module headers contain RFC section references