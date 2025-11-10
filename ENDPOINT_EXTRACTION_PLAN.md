# Endpoint Extraction Plan - Detailed Task Breakdown

**Phase 4b.5 Sessions 2-12**
**Created**: 2025-11-07 (Session 1)

## Overview

This plan breaks down the extraction of `endpoint.zig` (3,698 lines) into **11 sessions** with specific, actionable tasks. Each session is designed to be completed independently with clear deliverables and test criteria.

---

## Session 2: Complete Analysis & Interface Finalization (Week 2)

### Goals
- Finalize interface design based on Session 1 analysis
- Create test framework for modular extraction
- Validate extraction approach with proof-of-concept

### Tasks

#### 1. Review and Validate Interface Design (1-2 hours)
- [ ] Review `ENDPOINT_EXTRACTION_INTERFACES.md`
- [ ] Verify context struct sizes (should be <10 fields each)
- [ ] Check for circular dependencies
- [ ] Validate function pointer signatures

#### 2. Create Test Framework (2-3 hours)
- [ ] Create `tests/unit/endpoint/test_incoming.zig` skeleton
- [ ] Implement mock SendFn and ScheduleTimerFn
- [ ] Create helper to build RxContext from test data
- [ ] Write first test: "decode Version Negotiation packet"

#### 3. Proof-of-Concept: Extract Version Negotiation (3-4 hours)
- [ ] Copy `processIncomingDatagram()` lines 1062-1090 to `endpoint/incoming.zig`
- [ ] Rename to `processVersionNegotiation()`
- [ ] Replace `self` with `ctx: *RxContext`
- [ ] Update all state accesses to use `ctx.*`
- [ ] Write unit test for VN processing
- [ ] Build and verify no regressions (811/818 tests still pass)

#### 4. Document Lessons Learned
- [ ] Update `ENDPOINT_EXTRACTION_PLAN.md` with findings
- [ ] Note any interface adjustments needed
- [ ] Estimate time for full RX extraction

### Deliverables
- ✅ Working `processVersionNegotiation()` in `incoming.zig`
- ✅ Test framework with 1 passing test
- ✅ No regressions (811/818 tests pass)
- ✅ Updated extraction plan with refined estimates

---

## Session 3: RX Pipeline - Short Header Extraction (Week 3)

### Goals
- Extract Short Header (1-RTT) processing from `processIncomingDatagram()`
- Implement connection lookup helpers
- Convert 2 short header tests

### Tasks

#### 1. Extract Connection Lookup Logic (2-3 hours)
- [ ] Create `endpoint/lookup.zig:findConnectionByDcid()`
  - Input: `conns`, `peer`, `dcid_bytes`
  - Output: `?*Connection`
  - Lines 1104-1195 from endpoint.zig
- [ ] Handle peer_hash + dcid_hash matching
- [ ] Implement NAT rebinding fallback (all connections, DCID-only match)
- [ ] Write unit test for connection lookup
- [ ] Enhance existing `lookup.zig` (currently 82 lines)

#### 2. Extract DCID Length Enumeration (2-3 hours)
- [ ] Create `tryDecryptWithDcidEnumeration()` helper in `incoming.zig`
  - Input: `bytes`, `rx_keys`, `largest_pn`, `cached_len`
  - Output: `DecodeResult` with discovered DCID length
  - Lines 1236-1264 from endpoint.zig
- [ ] Implement systematic 0-20 length enumeration
- [ ] Cache successful length in connection
- [ ] Write unit test for DCID discovery

#### 3. Extract Short Header Processing (3-4 hours)
- [ ] Create `processShortHeader()` in `incoming.zig`
  - Lines 1092-1671 from endpoint.zig
  - ~600 lines
- [ ] Use `findConnectionByDcid()` for lookup
- [ ] Use `tryDecryptWithDcidEnumeration()` for decryption
- [ ] Handle key updates (current/next/prev keys)
- [ ] Extract frame parsing to next session
- [ ] For now, keep frame loop inline but mark for extraction

#### 4. Write Tests (1-2 hours)
- [ ] Test: Short header connection lookup by DCID
- [ ] Test: DCID length enumeration (Bug #6 regression)
- [ ] Convert placeholder test: "RFC 9000 §17.3 - Short header format"
- [ ] Convert placeholder test: "RFC 9000 §12.3 - Packet number encoding"

### Deliverables
- ✅ `lookup.zig:findConnectionByDcid()` with tests
- ✅ `incoming.zig:processShortHeader()` with tests
- ✅ 2 placeholder tests converted (short header + PN encoding)
- ✅ Build: 813/818 tests passing (+2 from 811)

---

## Session 4: Frame Handler Extraction (Week 3-4)

### Goals
- Extract frame processing from short header loop
- Create standalone frame handler module
- Convert 2 frame processing tests

### Tasks

#### 1. Create Frame Handler Module (3-4 hours)
- [ ] Create `endpoint/frame_handler.zig`
- [ ] Define `FrameContext` struct
- [ ] Implement `processFrame()` dispatcher
- [ ] Extract handlers from lines 1361-1475:
  - `handleStreamFrame()` (lines 1377-1392)
  - `handleAckFrame()` (lines 1412-1422)
  - `handlePathChallenge()` (lines 1449-1463)
  - `handlePathResponse()` (lines 1464-1468)
  - `handleMaxData()` (lines 1436-1439)
  - `handleMaxStreamData()` (lines 1430-1435)
  - `handleNewConnectionId()` (lines 1366-1371)
  - `handleRetireConnectionId()` (lines 1372-1376)
  - `handleHandshakeDone()` (lines 1423-1426, 1483-1488)
  - `handleConnectionClose()` (lines 1428-1429, 1489-1492)
  - `handleDatagram()` (lines 1393-1411)

#### 2. Integrate with processShortHeader() (1-2 hours)
- [ ] Replace inline frame loop with `frame_handler.processFrame()`
- [ ] Create `FrameContext` from `RxContext`
- [ ] Pass connection, peer, space

#### 3. Write Tests (2-3 hours)
- [ ] Test: Stream frame processing
- [ ] Test: ACK frame with recovery integration
- [ ] Test: PATH_CHALLENGE response generation
- [ ] Convert placeholder test: "RFC 9000 §19.8 - STREAM frame processing"
- [ ] Convert placeholder test: "RFC 9000 §19.3 - ACK frame parsing"

### Deliverables
- ✅ `frame_handler.zig` with 11 handlers (~300 lines)
- ✅ `processShortHeader()` simplified (frame loop removed)
- ✅ 2 placeholder tests converted (STREAM + ACK)
- ✅ Build: 815/818 tests passing (+2 from 813)

---

## Session 5: Initial Packet Extraction Part 1 (Week 4)

### Goals
- Extract Initial packet header parsing
- Extract connection creation logic
- Extract address validation

### Tasks

#### 1. Extract Initial Header Parsing (2-3 hours)
- [ ] Create `parseInitialHeader()` in `incoming.zig`
  - Lines 1682-1694 from endpoint.zig
  - Parse DCID, SCID lengths and values
  - Return structured header info
- [ ] Write unit test for header parsing

#### 2. Extract Connection Creation (3-4 hours)
- [ ] Create `createServerConnection()` in `server.zig`
  - Lines 1734-1850 from endpoint.zig
  - Allocate Connection struct
  - Set version, CIDs
  - Generate random SCID
  - Configure TLS certificate
  - Set transport parameters
  - Apply AEAD limits
- [ ] Update signature to use `ServerContext`
- [ ] Write unit test for server connection creation

#### 3. Extract Address Validation (2-3 hours)
- [ ] Create `endpoint/token.zig` module (enhance existing `token.zig`)
- [ ] Move token validation logic (lines 1954-1966)
- [ ] Move Retry generation logic (lines 1975-1990)
- [ ] Write tests for token validation and Retry

#### 4. Initial Packet Skeleton (1-2 hours)
- [ ] Create `processInitial()` in `incoming.zig`
- [ ] Use `parseInitialHeader()`
- [ ] Use `createServerConnection()` for new connections
- [ ] Use token validation
- [ ] Defer key derivation and decryption to Session 6

### Deliverables
- ✅ `parseInitialHeader()` with tests
- ✅ `server.zig:createServerConnection()` with tests
- ✅ `token.zig` enhanced with validation/Retry
- ✅ `processInitial()` skeleton (no decryption yet)
- ✅ Build: 815/818 tests passing (no new tests yet)

---

## Session 6: Initial Packet Extraction Part 2 - TLS Integration (Week 5)

### Goals
- Extract Initial packet decryption
- Extract CRYPTO frame processing
- Implement TLS handshake integration
- Convert 3 Initial packet tests

### Tasks

#### 1. Extract Initial Key Derivation (2-3 hours)
- [ ] Create `deriveInitialKeys()` in `incoming.zig`
  - Lines 1886-1938 from endpoint.zig
  - Handle role-oriented derivation (client vs server)
  - Use original DCID (ODCID) per RFC 9000 §5.2
  - Cache keys in connection
- [ ] Write unit test with RFC 9001 A.1 test vectors

#### 2. Extract Initial Packet Decryption (3-4 hours)
- [ ] Create `decryptInitialPacket()` in `incoming.zig`
  - Lines 1940-2089 from endpoint.zig
  - Parse token length, length field
  - Enumerate PN lengths 1-4
  - Call `packet.unprotectInitialLong()`
  - Return decrypted payload
- [ ] Write unit test for decryption

#### 3. Create TLS Integration Module (3-4 hours)
- [ ] Create `endpoint/handshake_integration.zig`
- [ ] Implement `processCryptoFrame()`
  - Extract CRYPTO frame handling from lines 2090-2900
  - Feed to `conn.tls.processHandshake()`
  - Derive secrets on TLS state transitions
  - Call `installHandshakeKeys()`, `installApplicationKeys()`
- [ ] Implement `installHandshakeKeys()`
  - Derive Handshake secrets using `ks.deriveClientServerHandshake()`
  - Store in `conn.hs_rx_keys`, `conn.hs_tx_keys`
- [ ] Implement `installApplicationKeys()`
  - Derive Application secrets using `ks.deriveClientServerApplication()`
  - Store in `conn.app_rx_keys`, `conn.app_tx_keys`

#### 4. Integrate TLS Processing into processInitial() (1-2 hours)
- [ ] Call `decryptInitialPacket()`
- [ ] Parse frames from decrypted payload
- [ ] Extract CRYPTO frames
- [ ] Call `handshake_integration.processCryptoFrame()`
- [ ] Handle TLS state machine transitions

#### 5. Write Tests (2-3 hours)
- [ ] Test: Initial key derivation with test vectors
- [ ] Test: Initial packet decryption
- [ ] Convert placeholder test: "RFC 9001 §5.2 - Initial key derivation"
- [ ] Convert placeholder test: "RFC 9000 §7 - Initial packet processing"
- [ ] Convert placeholder test: "RFC 9001 §4 - CRYPTO frame processing"

### Deliverables
- ✅ `deriveInitialKeys()` with test vector validation
- ✅ `decryptInitialPacket()` with tests
- ✅ `handshake_integration.zig` with key installation
- ✅ `processInitial()` complete with TLS integration
- ✅ 3 placeholder tests converted (Initial key + processing + CRYPTO)
- ✅ Build: 818/818 tests passing (+3 from 815) 🎯

---

## Session 7: Transport Parameters Integration (Week 5-6)

### Goals
- Extract transport parameter encoding/decoding from TLS flow
- Integrate TP validation
- Convert 3 transport parameter tests

### Tasks

#### 1. Enhance Transport Params Module (2-3 hours)
- [ ] Review existing `transport_params.zig` (354 lines)
- [ ] Add validation helpers:
  - `validate()` - Check required parameters present
  - `checkLimits()` - Verify values within allowed ranges
  - `apply()` - Apply peer TP to connection state
- [ ] Write unit tests for validation

#### 2. Integrate TP into TLS Handshake (2-3 hours)
- [ ] In `handshake_integration.processCryptoFrame()`:
  - Extract TP from TLS extension (ServerHello/EncryptedExtensions)
  - Call `TransportParams.decode()`
  - Call `validate()`, `checkLimits()`
  - Call `apply()` to update connection limits
- [ ] Handle TP errors (close connection with TRANSPORT_PARAMETER_ERROR)

#### 3. Add TP Encoding for Client (2-3 hours)
- [ ] In `client.zig:clientSendInitialProbe()`:
  - Build client TP
  - Call `TransportParams.encode()`
  - Pass to `tls.writeClientHello()` as extension
- [ ] Verify TP roundtrip (encode → send → receive → decode)

#### 4. Write Tests (2-3 hours)
- [ ] Convert placeholder test: "RFC 9000 §18.2 - Transport parameter encoding"
- [ ] Convert placeholder test: "RFC 9000 §7.4 - Transport parameter validation"
- [ ] Convert placeholder test: "RFC 9000 §18.2 - Required parameters check"

### Deliverables
- ✅ `transport_params.zig` enhanced with validation
- ✅ TP integrated into TLS handshake flow
- ✅ 3 placeholder tests converted (TP encoding + validation + required)
- ✅ Build: 821/821 tests passing (+3 from 818, includes new TP tests)

---

## Session 8: Handshake Packet Extraction (Week 6)

### Goals
- Extract Handshake packet processing
- Implement server response generation
- Test full handshake flow

### Tasks

#### 1. Extract Handshake Packet Processing (3-4 hours)
- [ ] Create `processHandshake()` in `incoming.zig`
  - Similar structure to `processInitial()`
  - Lines 2901-3100 from endpoint.zig
  - Parse Handshake header
  - Derive Handshake keys
  - Decrypt packet
  - Extract CRYPTO frames
  - Feed to TLS

#### 2. Implement Server Response Generation (3-4 hours)
- [ ] Create `sendServerHello()` in `handshake_integration.zig`
  - Build ServerHello message
  - Encode transport parameters
  - Create CRYPTO frame
  - Encrypt in Initial packet
  - Send to client
- [ ] Create `sendHandshakeDone()` in `handshake_integration.zig`
  - Build HANDSHAKE_DONE frame
  - Encrypt in 1-RTT packet
  - Send to client

#### 3. Test Full Handshake (2-3 hours)
- [ ] Test: Client Initial → Server Initial response
- [ ] Test: Client Handshake → Server Handshake response
- [ ] Test: Server HANDSHAKE_DONE → Client receives
- [ ] Integration test: Full handshake completion

### Deliverables
- ✅ `processHandshake()` complete
- ✅ `sendServerHello()` and `sendHandshakeDone()` implemented
- ✅ Full handshake integration tests passing
- ✅ Build: 821/821 tests passing

---

## Session 9: PTO Probe Extraction (Week 7)

### Goals
- Extract PTO probe generation from endpoint.zig
- Implement probe payload builders
- Test PTO probe generation

### Tasks

#### 1. Extract PTO Probe Generation (3-4 hours)
- [ ] Move `sendPtoProbe()` from endpoint.zig line 3392 to `pto.zig`
- [ ] Update signature to use `PtoContext`
- [ ] Extract probe payload building:
  - `buildInitialProbe()` - PING + CRYPTO
  - `buildHandshakeProbe()` - PING + CRYPTO
  - `buildApplicationProbe()` - PING + STREAM

#### 2. Integrate with Timer System (2-3 hours)
- [ ] Update `processExpiredTimers()` to use `pto.sendPtoProbe()`
- [ ] Create `PtoContext` from timer callback
- [ ] Pass connection, allocator, send_fn

#### 3. Write Tests (2-3 hours)
- [ ] Test: Initial PTO probe generation
- [ ] Test: Handshake PTO probe generation
- [ ] Test: Application PTO probe with STREAM data
- [ ] Test: PTO timer re-arming (exponential backoff)

### Deliverables
- ✅ `pto.zig` enhanced with full implementation (~200 lines)
- ✅ `sendPtoProbe()` extracted and tested
- ✅ Timer integration updated
- ✅ Build: 821/821 tests passing

---

## Session 10: Connection Lifecycle Extraction (Week 8)

### Goals
- Extract connection cleanup logic
- Implement stale connection detection
- Create lifecycle management module

### Tasks

#### 1. Create Lifecycle Module (2-3 hours)
- [ ] Create `endpoint/lifecycle.zig`
- [ ] Move `closeStaleConnectionsForPeer()` (line 3452)
- [ ] Move `pruneClosed()` (line 3515)
- [ ] Update signatures to use `LifecycleContext`

#### 2. Enhance Connection Cleanup (2-3 hours)
- [ ] Add `retireConnection()` - Move from active to retired
- [ ] Add `destroyConnection()` - Final cleanup and deallocation
- [ ] Handle timer cleanup during retirement
- [ ] Handle CID table cleanup

#### 3. Integrate with Endpoint (1-2 hours)
- [ ] Update `deinit()` to use lifecycle module
- [ ] Update connection creation to call `closeStaleConnectionsForPeer()`
- [ ] Add periodic `pruneClosed()` call

#### 4. Write Tests (2-3 hours)
- [ ] Test: Close stale connections for same peer
- [ ] Test: Prune closed connections from table
- [ ] Test: Retire connection cleans up timers
- [ ] Test: Connection lifecycle (create → active → closed → retired → destroyed)

### Deliverables
- ✅ `lifecycle.zig` created (~200 lines)
- ✅ Connection cleanup logic extracted
- ✅ Lifecycle tests passing
- ✅ Build: 821/821 tests passing

---

## Session 11: Platform I/O Consolidation (Week 9)

### Goals
- Consolidate platform-specific poll implementations
- Extract error queue handling
- Complete I/O module

### Tasks

#### 1. Enhance I/O Module (3-4 hours)
- [ ] Move `drainReadable()` from endpoint.zig line 719 to `io.zig`
- [ ] Move `drainErrorQueue()` from endpoint.zig line 828 to `io.zig`
- [ ] Move platform poll backends:
  - `poll_epoll_backend()` (line 939)
  - `poll_kqueue_backend()` (line 1010)
  - `poll_iocp_backend()` (line 1027)

#### 2. Create I/O Context Pattern (2-3 hours)
- [ ] Define `IoContext` struct
- [ ] Update `sendTo()` to use `IoContext`
- [ ] Update `drainReadable()` to accept callback
- [ ] Update error queue to accept callback

#### 3. Integrate with Main Poll Loop (1-2 hours)
- [ ] Simplify `poll()` in endpoint.zig
- [ ] Delegate to `io.poll_epoll()`, etc.
- [ ] Pass process callback

#### 4. Write Tests (1-2 hours)
- [ ] Test: drainReadable with mock socket
- [ ] Test: ICMP PTB error queue parsing
- [ ] Test: Platform poll integration

### Deliverables
- ✅ `io.zig` expanded to ~400 lines
- ✅ Platform I/O fully modular
- ✅ `endpoint.zig` poll loop simplified
- ✅ Build: 821/821 tests passing

---

## Session 12: Finalization and Documentation (Week 10)

### Goals
- Complete all remaining extraction
- Finalize endpoint.zig as thin coordinator
- Update documentation
- Verify all tests passing

### Tasks

#### 1. Final Cleanup (2-3 hours)
- [ ] Remove extracted code from endpoint.zig
- [ ] Keep only thin wrapper methods
- [ ] Verify endpoint.zig is <500 lines
- [ ] Update all imports and exports

#### 2. Documentation Updates (2-3 hours)
- [ ] Update `CLAUDE.md` with new module structure
- [ ] Update `MIGRATION_TO_MODULAR_API.md`
- [ ] Create `ENDPOINT_ARCHITECTURE.md` with diagrams
- [ ] Update `REFACTORING_STATUS.md`

#### 3. Test Verification (2-3 hours)
- [ ] Run full test suite: `zig build test`
- [ ] Verify 821/821 tests pass (or more if new tests added)
- [ ] Check server tests: expect 70/70 (100%)
- [ ] Verify no regressions

#### 4. Update PHASE_4_STATUS.md (1-2 hours)
- [ ] Document Phase 4b.5 completion
- [ ] List all extracted modules
- [ ] Record metrics:
  - Lines before: 3,698
  - Lines after: ~500
  - Modules created: 10+
  - Tests converted: 38 placeholder → real
  - Test coverage: 70/70 server tests (100%)

#### 5. Create Phase 5 Plan (1-2 hours)
- [ ] Identify next phase goals
- [ ] Plan remaining modularization work
- [ ] Document future improvements

### Deliverables
- ✅ `endpoint.zig` reduced to ~500 lines
- ✅ All modules extracted and tested
- ✅ Build: 821+ tests passing, 70/70 server tests (100%)
- ✅ Documentation complete and up-to-date
- ✅ Phase 4b.5 marked COMPLETE
- ✅ Phase 5 plan created

---

## Progress Tracking

**IMPORTANT**: See `GAP_ANALYSIS.md` for detailed analysis of actual vs planned implementation (created 2025-11-10).

### Module Extraction Status (ACTUAL as of 2025-11-10)

| Module | Planned | Actual | Status | Session | Gap |
|--------|---------|--------|--------|---------|-----|
| `incoming.zig` | 246 → ~800 | **2,608** | ✅ Complete (326%) | 3-6 | None |
| `frame_handler.zig` | 0 → ~300 | **395** | ✅ Complete (132%) | 4 | None |
| `handshake_integration.zig` | 0 → ~400 | **793** | ✅ Complete (198%) | 6-8 | None |
| `client.zig` | 88 → ~200 | **95** | ⚠️ Partial (48%) | 5,7 | TP encoding |
| `server.zig` | 67 → ~150 | **387** | ✅ Complete (258%) | 5 | None |
| `pto.zig` | 17 → ~200 | **260** | ✅ Complete (130%) | 9 | None |
| `lifecycle.zig` | 0 → ~200 | **285** | ✅ Complete (143%) | 10 | None |
| `io.zig` | 103 → ~400 | **383** | ✅ Complete (96%) | 11 | None |
| `lookup.zig` | 82 → ~150 | **209** | ✅ Complete (139%) | 3 | None |
| `timer.zig` | 63 → ~100 | **121** | ✅ Complete (121%) | - | None |
| `utils.zig` (bonus) | Not planned | **84** | ✅ Bonus | 10+ | None |
| `types.zig` (bonus) | Not planned | **94** | ✅ Bonus | 10+ | None |
| `endpoint.zig` (coordinator) | Not planned | **69** | ✅ Bonus | 10+ | None |
| **endpoint.zig (main)** | **3,698 → ~500** | **2,867** | **❌ Partial (574%)** | **All** | **~2,367 lines unextracted** |

### Test Conversion Status (NEEDS AUDIT - See GAP_ANALYSIS.md)

| Test Category | Placeholder | Converted | Session | Status |
|---------------|-------------|-----------|---------|--------|
| Short Header | 2 | ⚠️ TBD | 3 | ⚠️ Need audit |
| Frame Processing | 2 | ⚠️ TBD | 4 | ⚠️ Need audit |
| Initial Packet | 3 | ⚠️ TBD | 6 | ⚠️ Need audit |
| Transport Params | 3 | ⚠️ TBD | 7 | ⚠️ Need audit |
| Handshake | 0 | ⚠️ TBD | 8 | ⚠️ Need audit |
| PTO | 0 | ⚠️ TBD | 9 | ⚠️ Need audit |
| **Total** | **10+** | **⚠️ Unknown** | **-** | **⚠️ AUDIT REQUIRED** |

**Build Status (2025-11-10)**: ✅ All tests passing, all interop tests completed

### Build Status Targets

| Session | Target | Description |
|---------|--------|-------------|
| 1 | 811/818 | Baseline (current) |
| 2 | 811/818 | No change (POC only) |
| 3 | 813/818 | +2 short header tests |
| 4 | 815/818 | +2 frame tests |
| 5 | 815/818 | No change (skeleton only) |
| 6 | 818/818 | +3 Initial tests 🎯 |
| 7 | 821/821 | +3 TP tests |
| 8-12 | 821+/821+ | Maintain 100% |

---

## Risk Mitigation

### Potential Challenges

1. **Circular Dependencies**
   - **Risk**: Modules depend on each other
   - **Mitigation**: Use context structs and function pointers

2. **State Management**
   - **Risk**: Lost state during extraction
   - **Mitigation**: Comprehensive unit tests for each extraction

3. **Test Failures**
   - **Risk**: Regressions during extraction
   - **Mitigation**: Run full test suite after each session

4. **Interface Changes**
   - **Risk**: Public API breaks
   - **Mitigation**: Keep Endpoint public API unchanged

5. **Time Overruns**
   - **Risk**: Sessions take longer than estimated
   - **Mitigation**: Each session is independent; adjust schedule as needed

---

## Success Metrics

### Technical Metrics
- ✅ `endpoint.zig` reduced from 3,698 → ~500 lines (86% reduction)
- ✅ No function exceeds 400 lines
- ✅ All modules use focused context structs (<10 fields)
- ✅ Build: 821+ tests passing (100%)
- ✅ Server tests: 70/70 (100%)

### Code Quality Metrics
- ✅ Average module size: ~250 lines (vs 3,698)
- ✅ Module count: 10+ (vs 1)
- ✅ Function size: max 400 lines (vs 2,256)
- ✅ Test coverage: comprehensive unit + integration

### Project Metrics
- ✅ Sessions completed: 12/12
- ✅ Placeholder tests converted: 38/38
- ✅ Documentation updated: 5+ files
- ✅ Phase 4b.5 marked COMPLETE

---

## Next Steps After Session 12

1. **Code Review**
   - Review all extracted modules
   - Check for optimization opportunities
   - Verify RFC compliance

2. **Performance Testing**
   - Benchmark RX/TX throughput
   - Check for performance regressions
   - Optimize hot paths if needed

3. **Integration Testing**
   - Test with real QUIC implementations
   - Verify interoperability
   - Check for edge cases

4. **Phase 5 Planning**
   - Identify remaining modularization work
   - Plan conn.zig extraction (if needed)
   - Consider advanced features (multipath, etc.)

---

## Conclusion

This plan provides a detailed roadmap for extracting endpoint.zig over **11 sessions** (Sessions 2-12). Each session has clear goals, specific tasks, and measurable deliverables. The plan prioritizes:

1. **Incremental Progress**: Each session builds on the previous
2. **Independent Work**: Sessions can be completed in any order (with dependencies noted)
3. **Test-Driven**: Every extraction is verified with tests
4. **Low Risk**: No breaking changes to public API
5. **High Value**: Unblocks 38 placeholder tests, achieves 100% server test coverage

**Estimated Effort**: 8-12 weeks at 1 session/week
**Estimated Time**: 80-120 hours total (8-10 hours/session)
**Risk Level**: Low (incremental, test-driven approach)
**Impact**: High (86% code reduction, 100% test coverage, full modularity)
