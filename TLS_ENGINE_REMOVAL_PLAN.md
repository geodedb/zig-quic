# TLS Engine Removal Plan

## Objective
Remove ALL legacy TLS Engine code paths and migrate completely to TLS Context API.

## Current State Analysis

### Connection Struct Fields (src/quic/conn.zig:467-470)
```zig
tls: tls13.Engine,           // Line 467 - TO BE REMOVED
tls_context: ?*tls13.Context = null,  // Line 470 - TO BE MADE REQUIRED
```

### Engine Usage Mapping

| Engine Field/Method | Context Equivalent | Location |
|---|---|---|
| `self.tls.ensureKeypair()` | Context manages internally via `client_priv`, `client_pub` | conn.zig:837 |
| `self.tls.setPeerFinishedCallback()` | Not needed - Context has built-in callbacks | conn.zig:839, 1026 |
| `self.tls.deinit()` | `self.tls_context.deinit()` | conn.zig:1027 |
| `self.tls.setLocalTransportParameters()` | `self.tls_context.setTransportParameters()` | conn.zig:1283 |
| `self.tls.peer_pub` | Access via `self.tls_context.client_pub` (for server) | conn.zig:1363, 1377, 1381 |
| `self.tls.onCryptoRecv()` | `self.tls_context.processCrypto()` | conn.zig:1364 |
| `self.tls.sh_seen` | Remove - not needed with Context | conn.zig:1387, 1388, 1395, 1437, 1443, 1453 |
| `self.tls.queueRealServerHello()` | Remove - Context handles internally | conn.zig:1390, 1439 |
| `self.tls.handshake_client_secret` | `self.tls_context.secrets.slot(.Handshake, .send)` | conn.zig:1402, 1405 |
| `self.tls.handshake_server_secret` | `self.tls_context.secrets.slot(.Handshake, .recv)` | conn.zig:1403, 1406 |
| `self.tls.computeHandshakeSecrets()` | Access secrets directly from Context | conn.zig:1421 |
| `self.tls.ch_recv` / `self.tls.ch_sent` | Check `self.tls_context.phase` or `state.client_hello` | conn.zig:1452 |
| `self.tls.finished_verified` | `self.tls_context.flags.peer_finished_verified` | conn.zig:1460, 1470, 1511, 1576, 1719 |
| `self.tls.finished_sent` | `self.tls_context.flags.local_finished_sent` | conn.zig:1461, 1470, 1511, 1719 |
| `self.tls.outbox` | `self.tls_context.pollCrypto()` | conn.zig:1473, 1509, 1720, 2905, 2918 |
| `self.tls.computeApplicationSecrets()` | `self.tls_context.secrets.slot(.Application, ...)` | conn.zig:1497, 1721 |
| `self.tls.getPeerTransportParameters()` | Access `peer_quic_transport_parameters` | conn.zig:1557 |
| `self.tls.alpn` | `self.tls_context.negotiatedAlpn()` | conn.zig:1565, 1731 |
| `self.tls.peer_tp` | Access `peer_quic_transport_parameters` | conn.zig:1738 |
| `self.tls.local_tp` | `self.tls_context.localTransportParameters()` | conn.zig:1745 |
| `self.tls.queueNewSessionTicket()` | Context method (check if exists) | conn.zig:2930 |

### handshake_integration.zig Usage
- Line 801-802: `conn.tls.sh_seen = true` - **Phase 21 compatibility code TO BE REMOVED**

## Migration Steps

### Step 1: Update Connection Struct Definition
```zig
// BEFORE:
tls: tls13.Engine,
tls_context: ?*tls13.Context = null,

// AFTER:
tls_context: *tls13.Context,
```

### Step 2: Update Connection Initialization
All places that create Connection must:
1. Always create TLS Context (no longer optional)
2. Remove Engine initialization
3. Remove Engine field from init

Files to update:
- `src/quic/endpoint/client.zig` - createClientConnection()
- `src/quic/endpoint/server.zig` - createServerConnection()

### Step 3: Replace Engine Method Calls

#### conn.zig Changes

**Line 837: Remove ensureKeypair()**
- Context manages keypair internally
- Remove this call entirely

**Lines 839, 1026: Remove setPeerFinishedCallback()**
- Context has built-in callbacks
- Remove these calls

**Line 1027: Update deinit()**
```zig
// BEFORE:
self.tls.deinit();

// AFTER:
self.tls_context.deinit();
```

**Line 1283: Update setLocalTransportParameters()**
```zig
// BEFORE:
try self.tls.setLocalTransportParameters(encoded);

// AFTER:
self.tls_context.setTransportParameters(encoded);
```

**Lines 1363-1381: Replace peer_pub checks**
```zig
// BEFORE:
const had_peer_pub = self.tls.peer_pub != null;
// ... later ...
if (!had_peer_pub and self.tls.peer_pub != null) {

// AFTER:
const had_client_hello = self.tls_context.state.client_hello != null;
// ... later ...
if (!had_client_hello and self.tls_context.state.client_hello != null) {
```

**Line 1364: Replace onCryptoRecv()**
```zig
// BEFORE:
self.tls.onCryptoRecv(hs);

// AFTER:
try self.tls_context.processCrypto(.Handshake, hs);
```

**Lines 1387-1453: Remove sh_seen checks and queueRealServerHello()**
- This entire section for ServerHello handling can be removed
- Context handles ServerHello internally via processCrypto()

**Lines 1402-1421: Update Handshake secret access**
```zig
// BEFORE:
if (self.tls.handshake_client_secret) |client_secret| {
    if (self.tls.handshake_server_secret) |server_secret| {

// AFTER:
const client_slot = self.tls_context.secrets.slot(.Handshake, .send);
const server_slot = self.tls_context.secrets.slot(.Handshake, .recv);

if (client_slot.valid and server_slot.valid) {
    const client_secret = client_slot.value;
    const server_secret = server_slot.value;
```

**Lines 1460-1461: REMOVE Phase 21 compatibility code**
```zig
// REMOVE THESE LINES:
self.tls.finished_verified = tls_ctx.flags.peer_finished_verified;
self.tls.finished_sent = tls_ctx.flags.local_finished_sent;
```

**Lines 1470, 1511, 1719: Update Finished flag checks**
```zig
// BEFORE:
if (self.tls.finished_verified and self.tls.finished_sent) {

// AFTER:
if (self.tls_context.flags.peer_finished_verified and self.tls_context.flags.local_finished_sent) {
```

**Lines 1473, 1509, 1720, 2905, 2918: Replace outbox checks**
```zig
// BEFORE:
if (self.tls.outbox.items.len == 0) {

// AFTER:
// Check if Context has pending CRYPTO data
// Context uses pollCrypto() to get outgoing data
// For now, assume no buffering needed - Context sends immediately via callbacks
```

**Lines 1473-1507: REMOVE Phase 21 Application secrets compatibility code**
Replace with direct Context access:
```zig
const client_slot = self.tls_context.secrets.slot(.Application, .send);
const server_slot = self.tls_context.secrets.slot(.Application, .recv);

const send_slot = if (self.role == .Client) client_slot else server_slot;
const recv_slot = if (self.role == .Client) server_slot else client_slot;

if (send_slot.valid and recv_slot.valid) {
    const client_secret = client_slot.value;
    const server_secret = server_slot.value;
    self.deriveAppKeys(client_secret, server_secret, self.version_v2);
}
```

**Lines 1517-1553: REMOVE Phase 21 HANDSHAKE_DONE compatibility code**
- This should be handled by normal handshake flow with Context

**Line 1557: Update getPeerTransportParameters()**
```zig
// BEFORE:
if (self.tls.getPeerTransportParameters()) |peer_tp_bytes| {

// AFTER:
if (self.tls_context.peer_quic_transport_parameters) |peer_tp_bytes| {
```

**Lines 1565, 1731: Update ALPN access**
```zig
// BEFORE:
if (self.tls.alpn) |a| {

// AFTER:
if (self.tls_context.negotiatedAlpn()) |a| {
```

**Line 1738: Update peer_tp access**
```zig
// BEFORE:
if (self.tls.peer_tp) |tp_view| return tp_view;

// AFTER:
if (self.tls_context.peer_quic_transport_parameters) |tp| return tp;
```

**Line 1745: Update local_tp access**
```zig
// BEFORE:
if (self.tls.local_tp) |tp_view| return tp_view;

// AFTER:
if (self.tls_context.localTransportParameters()) |tp| return tp;
```

**Line 2930: Update queueNewSessionTicket()**
```zig
// BEFORE:
self.tls.queueNewSessionTicket() catch |e| {

// AFTER:
// Check if Context has session ticket support
// May need to add this to Context API or remove if not supported
```

#### handshake_integration.zig Changes

**Lines 801-802: REMOVE Phase 21 compatibility code**
```zig
// REMOVE THESE LINES:
conn.tls.sh_seen = true;
```

### Step 4: Update Tests
Tests that check Engine state must be updated:
- Remove checks for `conn.tls.sh_seen`
- Replace with Context state checks: `conn.tls_context.flags.*`, `conn.tls_context.phase`, etc.

### Step 5: Remove Engine Import and Type
- Remove `const tls13 = @import("quic_tls13");` if Engine-only
- Or update to only import Context: `const Context = tls13.Context;`

### Step 6: Clean Up Build System
- Ensure no legacy Engine dependencies remain
- Update any conditional compilation flags

## Expected Benefits

1. **Simpler codebase**: Single TLS implementation path
2. **Better maintainability**: No more sync between Engine and Context
3. **Clearer semantics**: Context API is more explicit about state
4. **Reduced code**: Remove ~100 lines of compatibility code
5. **Better testing**: Tests check actual Context state, not proxy flags

## Risks and Mitigation

**Risk**: Tests may fail initially due to state check changes
**Mitigation**: Update tests incrementally, verify each module

**Risk**: Context might not have all Engine features
**Mitigation**: Identify missing features and add to Context API first

**Risk**: Performance regression
**Mitigation**: Profile before/after, Context should be equivalent or better

## Testing Strategy

1. Run unit tests after each major change
2. Run integration tests after Connection struct changes
3. Run full test suite after complete migration
4. Compare test pass rate before/after

## Success Criteria

- ✓ All `self.tls.*` Engine references removed from codebase
- ✓ Connection struct no longer has `tls: Engine` field
- ✓ `tls_context` is required (not optional)
- ✓ All tests passing (1850+ tests)
- ✓ No legacy Engine imports remaining
- ✓ Phase 21 compatibility code completely removed

