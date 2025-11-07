# Endpoint Function-to-Subsystem Mapping

**Phase 4b.5 Session 1 Analysis**
**Date**: 2025-11-07
**File**: `src/quic/endpoint.zig` (3,698 lines)

## Executive Summary

The `endpoint.zig` monolith contains **44 functions** organized into **8 major subsystems**. The largest function `processIncomingDatagram()` spans **~2,256 lines** (lines 1044-3300) and contains the entire RX packet processing pipeline.

### Extraction Challenge

**Critical Dependency**: Almost all functions depend on the `Endpoint` struct's state:
- `allocator: *std.mem.Allocator` - Memory management
- `conns: std.AutoHashMap(Key, *conn_mod.Connection)` - Connection table
- `sock_fd: posix.socket_t` - UDP socket
- `timers: std.ArrayList(Timer)` - Timer heap
- `cfg: cfg.QuicConfig` - Configuration
- `accepted: std.ArrayList(*conn_mod.Connection)` - Server accept queue
- `test_capture_enabled: bool` - Test mode flag
- `epoll_fd: ?posix.fd_t` - Platform event loop handle

**Extraction Strategy**:
1. Keep Endpoint struct as thin coordinator
2. Extract subsystem logic to standalone modules
3. Pass focused context structs instead of full Endpoint pointer

---

## 1. RX Packet Pipeline (Lines 1044-3300, ~2,256 lines)

### Functions

| Function | Lines | Description | RFC Reference |
|----------|-------|-------------|---------------|
| `processIncomingDatagram()` | 1044-3300 | Main RX packet processor | RFC 9000 §12-17 |
| `recvFrom()` | 467-473 | UDP receive syscall wrapper | - |
| `drainReadable()` | 719-827 | Read all available datagrams | - |

### Detailed Breakdown of `processIncomingDatagram()`

This **2,256-line monolithic function** contains the entire RX pipeline:

**Lines 1044-1091**: Version Negotiation (VN) packet handling
- Decode VN packet (RFC 9000 §6, §17.2.1)
- Validate VN using `packet.shouldAcceptVersionNegotiation()`
- Select compatible version (v1 or v2)
- Trigger re-send of Initial with new version

**Lines 1092-1671**: Short header (1-RTT) packet processing
- **Lines 1104-1195**: Connection lookup by DCID
  - Hash peer address
  - Iterate connection table to find DCID match
  - Prefer connections with both app RX/TX keys (server prioritization)
  - Fallback: NAT rebinding/migration by DCID alone (RFC 9000 §9.3)
- **Lines 1196-1319**: DCID length enumeration and decryption
  - Try cached `expected_rx_dcid_len` first
  - On failure: enumerate lengths 0-20 systematically (Bug #6 fix)
  - Key update handling: try current → NEXT → prev keys
  - Stateless reset token detection
- **Lines 1320-1475**: Frame parsing and processing
  - PING, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID
  - STREAM, DATAGRAM frames
  - ACK/ACK_ECN with recovery integration
  - HANDSHAKE_DONE (drop Handshake keys)
  - PATH_CHALLENGE/PATH_RESPONSE
  - MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS_*
- **Lines 1476-1543**: ACK generation and sending
  - Build ACK/ACK_ECN frames
  - Respect amplification limits (RFC 9000 §8.1)
  - Piggyback MAX_* and NEW_CONNECTION_ID frames
  - Pacing logic
- **Lines 1544-1671**: ACK-only packets and ECN handling
  - ECN bit extraction and reporting
  - Amplification-gated ACK emission

**Lines 1672-3300**: Long header packet processing
- **Lines 1678-2089**: Initial packet processing
  - Parse DCID, SCID, token
  - Connection lookup/creation
  - Server twin synthesis (single-endpoint test scenarios)
  - Address validation via token (RFC 9000 §8.1)
  - Retry packet emission (if configured)
  - Initial key derivation (using original DCID)
  - Header protection removal
  - PN length enumeration (1-4 bytes)
- **Lines 2090-2900**: CRYPTO frame processing and TLS handshake
  - Decrypt Initial/Handshake packets
  - Extract CRYPTO frames
  - Feed to TLS 1.3 state machine
  - Derive Handshake/Application secrets
  - Install keys
  - Generate ServerHello/Finished
  - Send HANDSHAKE_DONE
- **Lines 2901-3100**: Handshake packet processing
  - Similar structure to Initial
  - Key derivation using Handshake secrets
  - TLS message processing
- **Lines 3101-3300**: Post-handshake logic
  - Connection state transitions
  - Timer management
  - Enqueue accepted connections

### Dependencies

**Endpoint State**:
- `allocator` - Memory for packet decryption buffers
- `conns` - Connection table lookup and insertion
- `accepted` - Enqueue server connections
- `cfg` - Retry, token, AEAD limit settings
- `test_capture_enabled` - Debug logging
- `sock_fd` - Send responses (via `sendTo()`)

**External Modules**:
- `packet.zig` - VN/Initial/Handshake/Short decoding
- `frame.zig` - Frame parsing
- `crypto_quic.zig` - Header protection, AEAD
- `vendor/ztls/` - TLS 1.3 handshake
- `transport_params.zig` - TP encoding/decoding
- `token.zig` - Retry token validation

### Extraction Plan

**Target**: Extract to `endpoint/incoming.zig` (already exists as 246-line stub)

**Refactoring**:
1. **Split by packet type** into separate functions:
   - `processVersionNegotiation()` (~50 lines)
   - `processShortHeader()` (~600 lines)
   - `processInitial()` (~800 lines)
   - `processHandshake()` (~600 lines)
2. **Extract frame processing** to `endpoint/frame_handler.zig`:
   - `handleStreamFrame()`
   - `handleAckFrame()`
   - `handlePathChallenge()`
   - etc.
3. **Extract connection lookup** to `endpoint/lookup.zig` (already exists):
   - Enhance existing lookup utilities
4. **Create focused context structs**:
   ```zig
   const RxContext = struct {
       allocator: *std.mem.Allocator,
       conns: *std.AutoHashMap(Key, *conn_mod.Connection),
       cfg: *const cfg.QuicConfig,
       send_fn: SendFn,
   };
   ```

**Test Migration**: 6 Initial packet tests + 6 transport param tests require this extraction.

---

## 2. TX Packet Pipeline (Lines 425-668, ~243 lines + sendPtoProbe)

### Functions

| Function | Lines | Description | RFC Reference |
|----------|-------|-------------|---------------|
| `sendTo()` | 425-466 | UDP send with ECN marking | RFC 3168, RFC 9000 §13.4 |
| `schedulePaced()` | 645-657 | Schedule paced packet transmission | RFC 9002 §7.7 |
| `sendPtoProbe()` | 3392-3451 | Generate and send PTO probe packets | RFC 9002 §6.2 |

### Detailed Breakdown

**`sendTo()` (lines 425-466)**:
- Sets ECN codepoint (ECT(0) default)
- Sends UDP datagram via `posix.sendto()`
- Captures outbound packets in test mode
- Returns bytes sent

**`schedulePaced()` (lines 645-657)**:
- Creates timer with `paced=true` and owned payload
- Schedules delayed transmission for congestion control pacing

**`sendPtoProbe()` (lines 3392-3451)**:
- Generates probe packets for PTO timer expiration
- Builds PING + CRYPTO/STREAM frames
- Encrypts with Initial/Handshake/Application keys
- Sends via `sendTo()`
- Re-arms PTO timer exponentially

### Dependencies

**Endpoint State**:
- `sock_fd` - UDP send syscall
- `captures` - Test mode packet capture
- `test_capture_enabled` - Test flag
- `timers` - Pacing timer scheduling

**External Modules**:
- `packet.zig` - Packet encoding
- `frame.zig` - Frame encoding
- `crypto_quic.zig` - Packet protection

### Extraction Plan

**Target**: Extract to `endpoint/pto.zig` (already exists as 17-line stub)

**Refactoring**:
1. Move `sendPtoProbe()` implementation to `pto.zig`
2. Keep `sendTo()` in `endpoint/io.zig` (already exists)
3. Move pacing logic to `endpoint/pacing.zig` (new module)

---

## 3. TLS Handshake Integration (Embedded in processIncomingDatagram + clientSendInitialProbe)

### Functions

| Function | Lines | Description | RFC Reference |
|----------|-------|-------------|---------------|
| `clientSendInitialProbe()` | 547-623 | Send Initial packet with ClientHello | RFC 9001 §4, RFC 9000 §7 |

### Detailed Breakdown

**`clientSendInitialProbe()` (lines 547-623)**:
- Derives Initial secrets from DCID (RFC 9001 §5.2)
- Builds TLS ClientHello via `conn.tls.writeClientHello()`
- Encodes transport parameters
- Creates CRYPTO frame + PADDING (to 1200 bytes, RFC 9000 §14.1)
- Encrypts Initial packet
- Sends via `sendTo()`
- Arms Initial PTO timer

**TLS Processing in `processIncomingDatagram()`** (lines 2090-2900):
- Extracts CRYPTO frames
- Reassembles out-of-order CRYPTO data
- Feeds to `conn.tls.processHandshake()`
- Derives secrets on key schedule transitions
- Installs Handshake/Application keys
- Sends ServerHello/Finished
- Sends HANDSHAKE_DONE (server-only)

### Dependencies

**Endpoint State**:
- `allocator` - CRYPTO buffer allocation
- `sock_fd` - Send handshake packets
- `timers` - PTO timer scheduling
- `cfg` - ALPN, certificate settings

**External Modules**:
- `vendor/ztls/tls13.zig` - TLS 1.3 state machine
- `vendor/ztls/key_schedule.zig` - Secret derivation
- `transport_params.zig` - TP encoding
- `crypto_quic.zig` - Initial secret derivation
- `connection/crypto_buffer.zig` - CRYPTO reassembly

### Extraction Plan

**Target**: Extract to `endpoint/handshake_integration.zig` (new module)

**Refactoring**:
1. Extract TLS message processing from `processIncomingDatagram()`
2. Create `processCryptoFrame()` helper
3. Create `installHandshakeKeys()` helper
4. Create `installApplicationKeys()` helper
5. Move `clientSendInitialProbe()` to `endpoint/client.zig`

**Test Migration**: 6 Initial packet tests + 6 transport param tests require this extraction.

---

## 4. Connection Lifecycle (Lines 475-546, ~71 lines + closeStaleConnectionsForPeer + pruneClosed)

### Functions

| Function | Lines | Description | RFC Reference |
|----------|-------|-------------|---------------|
| `acceptFrom()` | 475-478 | Create server connection from peer | RFC 9000 §7 |
| `pushAccepted()` | 480-483 | Enqueue accepted connection | - |
| `popAccepted()` | 485-489 | Dequeue accepted connection | - |
| `connectTo()` | 501-505 | Create basic client connection struct | RFC 9000 §7 |
| `connectClient()` | 507-546 | Create and initialize client connection | RFC 9000 §7 |
| `closeStaleConnectionsForPeer()` | 3452-3514 | Close duplicate connections | - |
| `pruneClosed()` | 3515-3530 | Remove closed connections from table | - |

### Detailed Breakdown

**`connectClient()` (lines 507-546)**:
- Allocates Connection struct
- Generates random 8-byte DCID/SCID (RFC 9000 §5.1.1)
- Sets version (v1 or v2)
- Applies config (CC, pacing, ALPN)
- Sets AEAD usage limits
- Registers in connection table
- Returns pointer

**`closeStaleConnectionsForPeer()` (lines 3452-3514)**:
- Identifies duplicate connections for same peer
- Closes older connections
- Prevents connection table pollution

**`pruneClosed()` (lines 3515-3530)**:
- Iterates connection table
- Removes entries marked `closed=true`
- Moves to `retired` list for delayed cleanup

### Dependencies

**Endpoint State**:
- `allocator` - Connection allocation
- `conns` - Connection table insertion/removal
- `accepted` - Accept queue
- `retired` - Closed connection list
- `cfg` - CC, ALPN, AEAD limit settings

**External Modules**:
- `conn.zig` - Connection struct

### Extraction Plan

**Target**: Extract to `endpoint/client.zig` and `endpoint/server.zig` (both already exist as stubs)

**Refactoring**:
1. Move `connectClient()` to `client.zig`
2. Move `acceptFrom()`, `pushAccepted()`, `popAccepted()` to `server.zig`
3. Move `closeStaleConnectionsForPeer()` to `endpoint/lifecycle.zig` (new)
4. Move `pruneClosed()` to `endpoint/lifecycle.zig`

---

## 5. Timer Coordination (Lines 395-668, ~273 lines + processExpiredTimers)

### Functions

| Function | Lines | Description | RFC Reference |
|----------|-------|-------------|---------------|
| `flushTimers()` | 395-398 | Clear all timers | - |
| `scheduleTimer()` | 624-632 | Generic timer scheduling | - |
| `scheduleConnPto()` | 634-643 | PTO timer scheduling | RFC 9002 §6.2 |
| `cancelTimer()` | 658-669 | Timer cancellation | - |
| `nextTimeoutFromTimers()` | 3323-3337 | Calculate next poll timeout | - |
| `processExpiredTimers()` | 3339-3382 | Process expired timers | RFC 9002 §6.2 |
| `forceExpireAllTimers()` | 3383-3391 | Force expire all timers (test-only) | - |

### Detailed Breakdown

**`scheduleConnPto()` (lines 634-643)**:
- Creates PTO timer with connection reference
- Specifies PN space (Initial, Handshake, Application)
- Adds to timer heap

**`processExpiredTimers()` (lines 3339-3382)**:
- Iterates timer heap
- Finds expired timers
- Dispatches by `TimerKind`:
  - `PtoInitial/PtoHandshake/PtoApp`: Calls `sendPtoProbe()`
  - `Pmtud`: Calls `conn.pmtudOnTimeout()`
  - `Generic` with `paced=true`: Sends paced payload
- Removes expired timers

### Dependencies

**Endpoint State**:
- `timers: std.ArrayList(Timer)` - Timer heap
- `next_timer_id: u64` - ID generator
- `conns` - Connection lookup for PTO

**External Modules**:
- `endpoint/timer.zig` (already exists as 63-line module with min-heap helpers)

### Extraction Plan

**Target**: Enhance `endpoint/timer.zig` (already exists)

**Refactoring**:
1. Move timer processing logic to `timer.zig`
2. Keep scheduling functions in main endpoint
3. Create `TimerContext` struct to avoid passing full Endpoint

---

## 6. Platform I/O (Lines 671-1043, ~372 lines)

### Functions

| Function | Lines | Description | Platform |
|----------|-------|-------------|----------|
| `poll()` | 671-717 | Main event loop dispatcher | All |
| `poll_epoll_backend()` | 939-1009 | Linux epoll implementation | Linux |
| `poll_kqueue_backend()` | 1010-1026 | BSD kqueue implementation | BSD/macOS |
| `poll_iocp_backend()` | 1027-1043 | Windows IOCP implementation | Windows |
| `drainReadable()` | 719-827 | Read all available datagrams | All |
| `drainErrorQueue()` | 828-911 | Read ICMP errors (Linux) | Linux |

### Detailed Breakdown

**`poll()` (lines 671-717)**:
- Dispatches to platform-specific backend
- Calculates timeout from timer heap
- Falls back to MSG_DONTWAIT-based polling if no backend

**`poll_epoll_backend()` (lines 939-1009)**:
- `epoll_wait()` with calculated timeout
- Calls `drainReadable()` on EPOLLIN
- Calls `drainErrorQueue()` on EPOLLERR (ICMP PTB)

**`drainReadable()` (lines 719-827)**:
- Loop with MSG_DONTWAIT to read all available datagrams
- Extracts ECN bits from ancillary data (if available)
- Calls `processIncomingDatagram()`

**`drainErrorQueue()` (lines 828-911)**:
- Reads ICMP messages from error queue (Linux-specific)
- Extracts PTB (Packet Too Big) messages
- Calls `handleIcmpPtb()`

### Dependencies

**Endpoint State**:
- `sock_fd` - UDP socket
- `epoll_fd` - Linux epoll handle
- `loop_backend` - Platform event loop type
- `timers` - Timeout calculation

**External Modules**:
- `posix` - System calls

### Extraction Plan

**Target**: Extract to `endpoint/io.zig` (already exists as 103-line module)

**Refactoring**:
1. Move `drainReadable()` to `io.zig`
2. Move `drainErrorQueue()` to `io.zig`
3. Move platform poll backends to `io.zig`
4. Keep main `poll()` as thin dispatcher

---

## 7. Error Handling (Lines 828-938, ~110 lines)

### Functions

| Function | Lines | Description | RFC Reference |
|----------|-------|-------------|---------------|
| `drainErrorQueue()` | 828-911 | Read ICMP errors | - |
| `handleIcmpPtb()` | 912-934 | Process ICMP PTB for PMTUD | RFC 9000 §14.2 |
| `testInjectIcmpPtb()` | 935-938 | Test injection for ICMP | - |

### Detailed Breakdown

**`handleIcmpPtb()` (lines 912-934)**:
- Extracts reported MTU from ICMP message
- Finds connection by quoted UDP payload
- Calls `conn.pmtudOnIcmpPtb(reported_mtu)`

### Dependencies

**Endpoint State**:
- `conns` - Connection lookup

**External Modules**:
- `connection/pmtud.zig` - PMTUD state machine

### Extraction Plan

**Target**: Extract to `endpoint/error_queue.zig` (new module)

**Refactoring**:
1. Move `drainErrorQueue()` to `error_queue.zig`
2. Move `handleIcmpPtb()` to `error_queue.zig`
3. Keep `testInjectIcmpPtb()` in main endpoint

---

## 8. State Machine Coordination (Lines 3300-3322, ~22 lines + init + deinit)

### Functions

| Function | Lines | Description | RFC Reference |
|----------|-------|-------------|---------------|
| `init()` | 144-297 | Endpoint initialization | - |
| `deinit()` | 298-394 | Endpoint cleanup | - |
| `onPathAddressChanged()` | 3300-3313 | Handle path migration | RFC 9000 §9 |
| `onPathValidated()` | 3314-3322 | Complete path validation | RFC 9000 §9 |

### Detailed Breakdown

**`init()` (lines 144-297)**:
- Creates UDP socket
- Binds to address
- Sets socket options (non-blocking, SO_REUSEADDR)
- Enables ECN and ICMP error queue (Linux)
- Creates epoll/kqueue/IOCP handle
- Determines endpoint role (client/server)
- Initializes connection table, timers, accept queue

**`deinit()` (lines 298-394)**:
- Closes all connections
- Frees timer payloads
- Closes socket
- Closes epoll handle
- Frees memory

**`onPathAddressChanged()` (lines 3300-3313)**:
- Updates connection peer address
- Triggers path validation (RFC 9000 §9.4)
- Sends PATH_CHALLENGE

**`onPathValidated()` (lines 3314-3322)**:
- Marks path as validated
- Resets anti-amplification state

### Dependencies

**Endpoint State**:
- All fields

**External Modules**:
- `posix` - System calls
- `connection/path.zig` - Path validation

### Extraction Plan

**Target**: Keep in main endpoint (orchestration logic)

**Refactoring**:
1. Extract socket setup to `endpoint/io.zig`
2. Extract path validation to `endpoint/path.zig` (new module)
3. Keep `init()`, `deinit()` as thin coordinators

---

## Test Utilities

| Function | Lines | Description |
|----------|-------|-------------|
| `captureClear()` | 400-404 | Clear packet capture |
| `captureLen()` | 406-408 | Get capture count |
| `capturePop()` | 410-414 | Pop captured packet |
| `testInject()` | 491-494 | Inject packet without ECN |
| `testInjectWithEcn()` | 496-499 | Inject packet with ECN |
| `testInjectIcmpPtb()` | 935-938 | Inject ICMP PTB |

**Extraction Plan**: Keep in main endpoint (test helpers)

---

## Dependency Graph Summary

```
┌─────────────────────────────────────────────────────────────┐
│                      Endpoint (Main)                         │
│  - Socket management (sock_fd, sock_family)                 │
│  - Connection table (conns)                                  │
│  - Timer coordination (timers)                               │
│  - Configuration (cfg)                                       │
│  - Accept queue (accepted)                                   │
└─────────────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│   RX Pipeline │  │   TX Pipeline │  │     Timers    │
│ (incoming.zig)│  │   (pto.zig)   │  │  (timer.zig)  │
│               │  │               │  │               │
│ - VN handling │  │ - PTO probes  │  │ - Scheduling  │
│ - Short/Long  │  │ - Pacing      │  │ - Expiry      │
│ - Frame parse │  │ - ECN marking │  │ - Cancellation│
└───────────────┘  └───────────────┘  └───────────────┘
        │                  │                  │
        └──────────────────┼──────────────────┘
                           ▼
                  ┌─────────────────┐
                  │ Platform I/O    │
                  │   (io.zig)      │
                  │ - sendTo/recvFrom│
                  │ - epoll/kqueue  │
                  │ - ICMP queue    │
                  └─────────────────┘
```

---

## Extraction Priority

### Week 1-2: Planning & Setup ✅ (This Document)
- ✅ Map all functions to subsystems
- ⏳ Design module interfaces
- ⏳ Create extraction plan

### Week 3-4: RX Pipeline Extraction
**Target**: `processIncomingDatagram()` → `endpoint/incoming.zig`
- Split into `processShortHeader()`, `processInitial()`, `processHandshake()`
- Extract frame handlers
- **Enables**: 6 Initial packet tests

### Week 5-6: TLS Integration Extraction
**Target**: CRYPTO processing → `endpoint/handshake_integration.zig`
- Extract `processCryptoFrame()`
- Extract key installation helpers
- Move `clientSendInitialProbe()` to `client.zig`
- **Enables**: 6 transport parameter tests

### Week 7-8: TX Pipeline Enhancement
**Target**: `sendPtoProbe()` → `endpoint/pto.zig`
- Move PTO probe generation
- Create pacing module

### Week 9-10: Connection Lifecycle
**Target**: Lifecycle functions → `endpoint/lifecycle.zig`
- Extract connection cleanup
- Extract accept queue management

### Week 11-12: Platform I/O
**Target**: Poll backends → `endpoint/io.zig`
- Move platform-specific code
- Consolidate I/O logic

---

## Key Insights

1. **Monolithic RX Function**: `processIncomingDatagram()` at 2,256 lines is the primary extraction target.

2. **State Dependencies**: Almost every function depends on `Endpoint` state. Must use focused context structs.

3. **Test Blockers**: 12 placeholder tests (6 Initial + 6 transport params) are blocked on RX/TLS extraction.

4. **Extraction Order**: RX → TLS → TX → Lifecycle → I/O (dependency-driven).

5. **Module Stubs Ready**: `incoming.zig`, `client.zig`, `server.zig`, `pto.zig`, `io.zig`, `lookup.zig`, `timer.zig` already exist with documentation.

---

## Next Steps (Week 1-2)

1. ✅ Complete this function mapping
2. ⏳ Design extraction interfaces (context structs, function signatures)
3. ⏳ Create detailed Week 3-4 work breakdown
4. ⏳ Set up test framework for gradual migration
5. ⏳ Document Phase 4b.5 Session 1 findings in PHASE_4_STATUS.md
