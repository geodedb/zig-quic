# QUIC STREAM Frame Implementation & Debugging Plan

## Executive Summary
STREAM frame handling code exists in the codebase but is not functioning correctly. The server receives STREAM frames from clients but `acceptStream()` finds no streams in the queue. This plan provides a systematic approach to debug, fix, test, and benchmark the complete STREAM frame lifecycle.

## RFC 9000 References

### Core Stream Specifications
- **Section 2**: Streams (Lines 495-645)
  - 2.1: Stream Types and Identifiers (Line 518)
  - 2.3: Stream Prioritization (Line 594)
  - 2.4: Operations on Streams (Line 609)

- **Section 3**: Stream States (Lines 645-910)
  - 3.1: Sending Stream States (Line 677)
  - 3.2: Receiving Stream States (Line 768)
  - 3.4: Bidirectional Stream States (Line 910)

- **Section 4**: Flow Control (Lines 1095-1208)
  - 4.1: Data Flow Control (Line 1106)
  - 4.4: Handling Stream Cancellation (Line 1149)
  - 4.5: Stream Final Size (Line 1165)

- **Section 19**: Frame Formats
  - 19.8: STREAM Frames (Line 6213-6308)
  - 19.10: MAX_STREAM_DATA Frames (Line 6309-6353)
  - 19.11: MAX_STREAMS Frames (Line 6354-6418)
  - 19.13: STREAM_DATA_BLOCKED Frames (Line 6419-6445)
  - 19.14: STREAMS_BLOCKED Frames (Line 6446-6490)

---

## Phase 1: Root Cause Analysis & Immediate Fix

### Objective
Identify why existing STREAM frame handling doesn't populate `incoming_stream_queue`

### Current Code Locations

#### 1. Frame Reception (src/quic/endpoint.zig)
**Line 1335-1347**: Application packet STREAM frame handler
```zig
// RFC 9000 §19.8: STREAM frames (0x08-0x0f) convey stream data
.stream => |s| {
    const off: u64 = s.offset orelse 0;
    if (conn.role == .Server) {
        std.debug.print("Server received STREAM frame - id={}, off={}, len={}, fin={}\n",
            .{ s.stream_id, off, s.data.len, s.fin });
    } else {
        std.debug.print("CLIENT received STREAM frame - id={}, off={}, len={}, fin={}\n",
            .{ s.stream_id, off, s.data.len, s.fin });
    }
    // Delegate to Connection for stream state management
    conn.pushStreamFrame(s.stream_id, off, s.data, s.fin) catch |err| {
        std.debug.print("pushStreamFrame failed: {}\n", .{err});
    };
    saw_any = true;
    saw_ack_eliciting = true;  // RFC 9000 §13.2: STREAM frames are ack-eliciting
},
```

**Action**: Add detailed debug logging to track if this code path is reached

#### 2. Stream Frame Processing (src/quic/conn.zig)
**Line 1655-1711**: `pushStreamFrame()` implementation
```zig
pub fn pushStreamFrame(self: *Connection, stream_id: u64, offset: u64, data: []const u8, fin: bool) !void {
    if (self.stream_recv_aborted) return; // ignore further data after RESET_STREAM

    std.debug.print("DEBUG pushStreamFrame: stream_id={}, offset={}, len={}, fin={}, role={}\n",
        .{ stream_id, offset, data.len, fin, self.role });

    // RFC 9000 §2.1: Check if this is a new peer-initiated stream
    const is_peer_initiated = self.isPeerInitiatedStream(stream_id);
    std.debug.print("is_peer_initiated={}, stream_known={}\n",
        .{ is_peer_initiated, self.isStreamKnown(stream_id) });

    // RFC 9000 §2.1: Client-initiated streams have even-numbered stream_id & 0x1 == 0
    if (is_peer_initiated and !self.isStreamKnown(stream_id)) {
        // Add to incoming queue if not already there
        std.debug.print("Queueing new incoming stream {}\n", .{stream_id});
        try self.queueIncomingStream(stream_id);
        std.debug.print("Queue now has {} streams\n", .{self.incoming_stream_queue.items.len});
    }
    // ... rest of implementation
}
```

**Action**: Verify this is being called and check why queue remains empty

#### 3. Stream Queue Management (src/quic/conn.zig)
**Line 2999-3009**: `isStreamKnown()` - checks if stream already tracked
**Line 3012-3035**: `queueIncomingStream()` - adds stream to incoming queue
**Line 3082-3116**: `acceptStream()` - removes stream from queue and returns to application

**Action**: Trace execution flow through these functions

### Debug Tasks
1. **Enable comprehensive logging**
   - Verify STREAM frames are decoded (endpoint.zig:1313)
   - Confirm `pushStreamFrame` is called (conn.zig:1658)
   - Check `isPeerInitiatedStream` returns true for stream ID 0
   - Verify `isStreamKnown` returns false for new streams
   - Confirm `queueIncomingStream` is reached
   - Check `incoming_stream_queue.append` succeeds

2. **Hypothesis Testing**
   - Test 1: Stream 0 might not be considered "peer-initiated" on server
   - Test 2: `ensureStreamRx` might mark stream as "known" before queueing
   - Test 3: `isPeerInitiatedStream` logic may be inverted

3. **Immediate Fix**
   - Location: `src/quic/conn.zig`, around line 1664
   - Check the implementation of `isPeerInitiatedStream()`
   - Verify stream ID 0 (client-initiated bidirectional) is correctly identified

### Expected Outcome
- Identify the exact line where stream queueing logic fails
- Apply targeted fix to populate `incoming_stream_queue`
- Verify fix with simple echo test

**Estimated Time**: 2-4 hours

---

## Phase 2: Complete Stream Lifecycle Implementation

### Objective
Ensure RFC 9000 compliance for full bidirectional stream lifecycle

### 2.1 Stream State Machine (RFC 9000 §3)

#### Location: src/quic/conn.zig (New struct/functions)

**Create StreamTxState enum**:
```zig
// RFC 9000 §3.1: Sending Stream States
const StreamTxState = enum {
    ready,      // Stream created, ready to send
    send,       // Application data being sent
    data_sent,  // All data sent, awaiting ACKs
    reset_sent, // RESET_STREAM sent
    reset_recvd,// RESET_STREAM acknowledged
};
```

**Create StreamRxState enum**:
```zig
// RFC 9000 §3.2: Receiving Stream States
const StreamRxState = enum {
    recv,           // Receiving data
    size_known,     // Final size known (FIN received)
    data_recvd,     // All data received and buffered
    reset_recvd,    // RESET_STREAM received
    reset_read,     // Application notified of reset
};
```

**Add to Connection struct** (around line 100):
```zig
// RFC 9000 §3: Stream state tracking
stream_tx_states: std.AutoHashMap(u64, StreamTxState),
stream_rx_states: std.AutoHashMap(u64, StreamRxState),
```

**Implementation Tasks**:
1. Initialize state maps in `Connection.init()`
2. Update states on frame send/receive
3. Validate state transitions per RFC 9000 Figure 3-4
4. Clean up closed streams after grace period

**Spec Reference**: RFC 9000 §3, Lines 645-910

### 2.2 Flow Control (RFC 9000 §4)

#### Location: src/quic/conn.zig (existing functions, need enhancement)

**Current implementations to enhance**:
- Line 1385-1389: `max_stream_data` frame handling (basic)
- Line 1390-1394: `max_data` frame handling (basic)
- Line 1698-1710: Flow control window updates (basic)

**Required additions**:

**A. Per-Stream Flow Control**:
```zig
// RFC 9000 §4.1: Track flow control limits per stream
pub fn updateStreamFlowControl(self: *Connection, stream_id: u64, max_data: u64) void {
    // Update peer's advertised limit for this stream
    const tx = self.stream_txs.getPtr(stream_id) orelse return;
    tx.peer_max_data = max_data;
    std.debug.print("Stream {} flow control: peer allows {} bytes\n",
        .{stream_id, max_data});
}

// RFC 9000 §4.1: Check if we can send more data on stream
pub fn canSendOnStream(self: *Connection, stream_id: u64, amount: u64) bool {
    const tx = self.stream_txs.get(stream_id) orelse return false;
    return (tx.sent_offset + amount) <= tx.peer_max_data;
}
```

**B. Connection-Level Flow Control**:
```zig
// RFC 9000 §4.1: Connection-wide flow control
pub fn canSendOnConnection(self: *Connection, amount: u64) bool {
    return (self.conn_send_total + amount) <= self.peer_max_data;
}
```

**C. MAX_STREAMS Enforcement**:
```zig
// RFC 9000 §4.6: Enforce concurrent stream limits
pub fn canOpenStream(self: *Connection, is_bidi: bool) bool {
    if (is_bidi) {
        const next_id = self.next_local_bidi_stream_id;
        const max_allowed = self.peer_max_streams_bidi * 4;
        return next_id <= max_allowed;
    } else {
        const next_id = self.next_local_uni_stream_id;
        const max_allowed = self.peer_max_streams_uni * 4;
        return next_id <= max_allowed;
    }
}
```

**Spec References**:
- RFC 9000 §4, Lines 1095-1208
- RFC 9000 §19.10 (MAX_STREAM_DATA), Line 6309
- RFC 9000 §19.11 (MAX_STREAMS), Line 6354

### 2.3 Stream Data Transmission

#### Location: src/quic/api.zig and src/quic/conn.zig

**Current implementation**: Line 257-299 in api.zig (writeStream)

**Enhancements needed**:

**A. Chunking for large writes** (api.zig:~280):
```zig
// RFC 9000 §19.8: STREAM frames limited by max_udp_payload
pub fn writeStream(conn: *Connection, stream_id: u64, data: []const u8) !usize {
    const tx = conn.stream_txs.getPtr(stream_id) orelse return error.InvalidStream;

    // RFC 9000 §4.1: Check stream-level flow control
    if (!conn.canSendOnStream(stream_id, data.len)) {
        return error.FlowControlBlocked;
    }

    // RFC 9000 §4.1: Check connection-level flow control
    if (!conn.canSendOnConnection(data.len)) {
        return error.FlowControlBlocked;
    }

    // Chunk data to fit within MTU minus overhead
    const max_chunk = conn.max_udp_payload - 50; // Reserve space for headers
    const to_send = @min(data.len, max_chunk);

    // Add to TX buffer
    try tx.buffer.append(conn.allocator.*, data[0..to_send]);
    tx.send_offset += to_send;
    conn.conn_send_total += to_send;

    return to_send;
}
```

**B. Retransmission handling** (conn.zig, new function):
```zig
// RFC 9000 §13.3: Retransmit lost STREAM frames
pub fn retransmitLostStreamData(self: *Connection, stream_id: u64, offset: u64, length: u64) !void {
    const tx = self.stream_txs.getPtr(stream_id) orelse return error.InvalidStream;

    // Retrieve data from offset in TX buffer
    const data = tx.buffer.items[offset..@min(offset + length, tx.buffer.items.len)];

    // Re-send as STREAM frame
    var fb = std.ArrayList(u8){};
    defer fb.deinit(self.allocator.*);
    const w = fb.writer(self.allocator.*);

    const fin = (offset + data.len == tx.buffer.items.len) and tx.want_fin;
    _ = (frame.Frame{ .stream = .{
        .stream_id = stream_id,
        .offset = offset,
        .fin = fin,
        .data = data
    } }).write(w) catch return;

    // Encode and send packet
    // ... (use existing packet encoding logic)
}
```

**Spec Reference**: RFC 9000 §19.8, Lines 6213-6308

### 2.4 Stream Reception & Reassembly

#### Location: src/quic/conn.zig

**Current implementation**: Line 1655-1711 (`pushStreamFrame`)

**Enhancements**:

**A. Out-of-order handling** (already exists in StreamRx.insert, verify):
```zig
// RFC 9000 §2.2: Stream data must be delivered in order
// Current implementation at StreamRx.insert() handles gaps
// VERIFY: gaps are stored and drained correctly when filled
```

**B. Flow control credit updates** (enhance line 1698-1710):
```zig
// RFC 9000 §4.1: Send MAX_STREAM_DATA when window consumed
if (s.recv_off >= (self.local_max_stream_data * 75 / 100)) {
    const new_limit = self.local_max_stream_data + (self.local_max_stream_data / 2);
    self.local_max_stream_data = new_limit;

    // Queue MAX_STREAM_DATA frame for transmission
    self.pending_max_stream_data.put(stream_id, new_limit) catch {};
}
```

**C. Connection flow control**:
```zig
// RFC 9000 §4.1: Send MAX_DATA when connection window consumed
if (self.conn_recv_total >= (self.local_max_data * 70 / 100)) {
    const bump = self.local_max_data / 4;
    self.local_max_data += bump;

    // Queue MAX_DATA frame for transmission
    self.pending_max_data = self.local_max_data;
}
```

**Spec Reference**: RFC 9000 §2.2, §4.1

---

## Phase 3: Frame Transmission & Reception

### 3.1 Outgoing Frame Generation

#### Location: src/quic/endpoint.zig or conn.zig (new function)

**Create frame scheduling logic**:
```zig
// RFC 9000 §13.1: Frame scheduling for packet assembly
pub fn gatherFramesForPacket(self: *Connection, space: EncryptionLevel, max_bytes: usize) ![]frame.Frame {
    var frames = std.ArrayList(frame.Frame){};
    var bytes_used: usize = 0;

    // Priority order per RFC 9000 §13.2:
    // 1. ACK frames (ack-eliciting packets received)
    // 2. Connection close/errors
    // 3. Flow control updates (MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS)
    // 4. STREAM frames (round-robin across active streams)
    // 5. PING (keep-alive)

    // 1. ACK frames
    if (self.shouldSendAck(space)) {
        const ack_frame = try self.buildAckFrame(space);
        const ack_size = estimateFrameSize(ack_frame);
        if (bytes_used + ack_size <= max_bytes) {
            try frames.append(ack_frame);
            bytes_used += ack_size;
        }
    }

    // 3. Flow control updates
    if (self.pending_max_data) |new_limit| {
        const fc_frame = frame.Frame{ .max_data = .{ .max = new_limit } };
        const fc_size = estimateFrameSize(fc_frame);
        if (bytes_used + fc_size <= max_bytes) {
            try frames.append(fc_frame);
            bytes_used += fc_size;
            self.pending_max_data = null;
        }
    }

    // Per-stream MAX_STREAM_DATA
    var it = self.pending_max_stream_data.iterator();
    while (it.next()) |entry| {
        const fc_frame = frame.Frame{ .max_stream_data = .{
            .stream_id = entry.key_ptr.*,
            .max = entry.value_ptr.*
        } };
        const fc_size = estimateFrameSize(fc_frame);
        if (bytes_used + fc_size <= max_bytes) {
            try frames.append(fc_frame);
            bytes_used += fc_size;
            _ = self.pending_max_stream_data.remove(entry.key_ptr.*);
        }
    }

    // 4. STREAM frames (round-robin)
    var stream_it = self.stream_txs.iterator();
    while (stream_it.next()) |entry| {
        const stream_id = entry.key_ptr.*;
        const tx = entry.value_ptr.*;

        if (tx.buffer.items.len == 0) continue;

        const available_space = max_bytes - bytes_used;
        if (available_space < 20) break; // Need minimum space for STREAM frame overhead

        const max_data = available_space - 16; // Reserve for frame header
        const to_send = @min(tx.buffer.items.len - tx.sent_offset, max_data);

        if (to_send > 0) {
            const offset = tx.sent_offset;
            const fin = (offset + to_send == tx.buffer.items.len) and tx.want_fin;
            const stream_frame = frame.Frame{ .stream = .{
                .stream_id = stream_id,
                .offset = if (offset > 0) offset else null,
                .fin = fin,
                .data = tx.buffer.items[offset..offset + to_send],
            } };

            try frames.append(stream_frame);
            tx.sent_offset += to_send;
            bytes_used += to_send + 16;
        }
    }

    return frames.toOwnedSlice();
}
```

**Spec Reference**: RFC 9000 §13.1-13.2, Lines 3423-3565

### 3.2 Incoming Frame Processing

Already exists at:
- **endpoint.zig:1319-1420**: Switch statement for Application frames
- **endpoint.zig:2114-2145**: Switch statement for Initial frames
- **endpoint.zig:3038-3067**: Switch statement for Handshake frames

**Action**: Verify all necessary frame types are handled in each space:
- Initial: CRYPTO, ACK, PADDING, CONNECTION_CLOSE
- Handshake: CRYPTO, ACK, PADDING, CONNECTION_CLOSE
- Application: STREAM, ACK, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, STREAM_DATA_BLOCKED, STREAMS_BLOCKED, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE, PATH_RESPONSE, CONNECTION_CLOSE, HANDSHAKE_DONE, PING, DATAGRAM

---

## Phase 4: Testing Strategy

### 4.1 Unit Tests

**Location**: `tests/stream_test.zig` (new file)

```zig
const std = @import("std");
const testing = std.testing;
const conn_mod = @import("quic").conn;

test "stream ID classification" {
    // RFC 9000 §2.1: Stream ID format
    // Client-initiated bidirectional: 0x00, 0x04, 0x08...
    // Server-initiated bidirectional: 0x01, 0x05, 0x09...
    // Client-initiated unidirectional: 0x02, 0x06, 0x0a...
    // Server-initiated unidirectional: 0x03, 0x07, 0x0b...

    var conn = try createTestConnection(.Server);
    defer conn.deinit();

    try testing.expect(conn.isPeerInitiatedStream(0));  // Client bidi
    try testing.expect(!conn.isPeerInitiatedStream(1)); // Server bidi
    try testing.expect(conn.isPeerInitiatedStream(2));  // Client uni
    try testing.expect(!conn.isPeerInitiatedStream(3)); // Server uni
}

test "stream queueing" {
    var conn = try createTestConnection(.Server);
    defer conn.deinit();

    try conn.queueIncomingStream(0);
    try testing.expectEqual(@as(usize, 1), conn.incoming_stream_queue.items.len);
    try testing.expectEqual(@as(u64, 0), conn.incoming_stream_queue.items[0]);

    // Duplicate queueing should be idempotent
    try conn.queueIncomingStream(0);
    try testing.expectEqual(@as(usize, 1), conn.incoming_stream_queue.items.len);
}

test "stream acceptance" {
    var conn = try createTestConnection(.Server);
    defer conn.deinit();

    try conn.queueIncomingStream(0);
    const stream_id = try conn.acceptStream();
    try testing.expectEqual(@as(u64, 0), stream_id);

    // Queue should now be empty
    try testing.expectError(error.WouldBlock, conn.acceptStream());
}

test "stream data push and read" {
    // RFC 9000 §2.2: Ordered delivery
    var conn = try createTestConnection(.Server);
    defer conn.deinit();

    const data = "Hello, QUIC!";
    try conn.pushStreamFrame(0, 0, data, false);

    var buf: [100]u8 = undefined;
    const n = try conn.readStream(0, &buf);
    try testing.expectEqual(data.len, n);
    try testing.expectEqualStrings(data, buf[0..n]);
}

test "stream out-of-order reassembly" {
    // RFC 9000 §2.2: Data must arrive in order but can be buffered
    var conn = try createTestConnection(.Server);
    defer conn.deinit();

    // Receive data out of order
    try conn.pushStreamFrame(0, 10, "world", false);
    try conn.pushStreamFrame(0, 0, "Hello ", false);
    try conn.pushStreamFrame(0, 6, "QUIC ", false);

    var buf: [100]u8 = undefined;
    const n = try conn.readStream(0, &buf);
    try testing.expectEqual(@as(usize, 16), n);
    try testing.expectEqualStrings("Hello QUIC world", buf[0..n]);
}

test "stream flow control blocking" {
    // RFC 9000 §4.1: Cannot exceed peer's advertised limit
    var conn = try createTestConnection(.Client);
    defer conn.deinit();

    conn.peer_max_stream_data = 10; // Peer allows only 10 bytes

    const data = "This is more than 10 bytes";
    try testing.expectError(error.FlowControlBlocked, conn.writeStream(0, data));

    // Should succeed with smaller data
    const small_data = "Small";
    const written = try conn.writeStream(0, small_data);
    try testing.expectEqual(@as(usize, 5), written);
}

test "MAX_STREAMS enforcement" {
    // RFC 9000 §4.6: Respect peer's stream limits
    var conn = try createTestConnection(.Client);
    defer conn.deinit();

    conn.peer_max_streams_bidi = 2; // Peer allows 2 bidirectional streams (IDs 0, 4)

    // Should succeed for streams 0 and 4
    try testing.expect(conn.canOpenStream(true)); // Stream 0
    conn.next_local_bidi_stream_id = 4;
    try testing.expect(conn.canOpenStream(true)); // Stream 4

    // Should fail for stream 8
    conn.next_local_bidi_stream_id = 8;
    try testing.expect(!conn.canOpenStream(true));
}
```

**Spec Coverage**:
- RFC 9000 §2.1 (Stream IDs): Line 518
- RFC 9000 §2.2 (Ordered Delivery): Line 538
- RFC 9000 §4.1 (Flow Control): Line 1106
- RFC 9000 §4.6 (Stream Limits): Line 1178

### 4.2 Integration Tests

**Location**: `tests/e2e_stream_test.zig` (new file)

```zig
test "bidirectional echo test" {
    // Full round-trip: client sends, server echoes, client receives
    const server_ep = try createTestEndpoint(.Server, "127.0.0.1:0");
    defer server_ep.deinit();

    const client_ep = try createTestEndpoint(.Client, "127.0.0.1:0");
    defer client_ep.deinit();

    // Connect
    const conn = try client_ep.connect(server_addr, "test.local");

    // Wait for handshake
    try waitForHandshake(client_ep, conn, 5000);

    // Send data
    const msg = "QUIC test message";
    const written = try conn.writeStream(0, msg);
    try testing.expectEqual(msg.len, written);

    // Flush
    try client_ep.flush(100);

    // Server accepts and echoes
    try server_ep.poll(100);
    const server_conn = try server_ep.tryAccept();
    const stream_id = try server_conn.acceptStream();

    var server_buf: [100]u8 = undefined;
    const n = try server_conn.readStream(stream_id, &server_buf);
    try testing.expectEqual(msg.len, n);

    _ = try server_conn.writeStream(stream_id, server_buf[0..n]);
    try server_ep.flush(100);

    // Client receives echo
    try client_ep.poll(100);
    var client_buf: [100]u8 = undefined;
    const m = try conn.readStream(0, &client_buf);
    try testing.expectEqual(msg.len, m);
    try testing.expectEqualStrings(msg, client_buf[0..m]);
}

test "multiple concurrent streams" {
    // RFC 9000 §2: Multiple streams multiplex over one connection
    // Test 4 concurrent bidirectional streams

    // ... (similar setup)

    var i: u64 = 0;
    while (i < 4) : (i += 1) {
        const stream_id = i * 4; // 0, 4, 8, 12
        var msg_buf: [50]u8 = undefined;
        const msg = try std.fmt.bufPrint(&msg_buf, "Stream {d} data", .{stream_id});

        _ = try conn.writeStream(stream_id, msg);
    }

    try client_ep.flush(100);
    try server_ep.poll(100);

    // Server should accept 4 streams
    i = 0;
    while (i < 4) : (i += 1) {
        const stream_id = try server_conn.acceptStream();
        try testing.expect(stream_id == i * 4);
    }
}

test "large data transfer" {
    // RFC 9000 §13: Test fragmentation and reassembly
    const large_data = try testing.allocator.alloc(u8, 100 * 1024); // 100 KB
    defer testing.allocator.free(large_data);

    // Fill with pattern
    for (large_data, 0..) |*byte, i| {
        byte.* = @truncate(i);
    }

    // Send in chunks (API will fragment automatically)
    var sent: usize = 0;
    while (sent < large_data.len) {
        const n = try conn.writeStream(0, large_data[sent..]);
        sent += n;
        try client_ep.flush(10);
        try server_ep.poll(10);
    }

    // Receive and verify
    const server_conn = try server_ep.tryAccept();
    const stream_id = try server_conn.acceptStream();

    var received = std.ArrayList(u8).init(testing.allocator);
    defer received.deinit();

    var buf: [4096]u8 = undefined;
    while (received.items.len < large_data.len) {
        const n = try server_conn.readStream(stream_id, &buf);
        if (n == 0) break;
        try received.appendSlice(buf[0..n]);
    }

    try testing.expectEqual(large_data.len, received.items.len);
    try testing.expectEqualSlices(u8, large_data, received.items);
}
```

### 4.3 Comprehensive Test Suite Enhancement

**Location**: `quic-test/test_client_comprehensive.go` and `cmd/quic-client-comprehensive.zig`

These already exist! Just need to ensure they work after the fix.

**Action**: Re-run after Phase 1 fix:
```bash
make e2e-comprehensive 2>&1 | tee e2e-comprehensive-fixed.log
```

**Expected results after fix**:
- All 8 Go tests pass
- All 6 Zig tests pass
- No timeout errors
- Stream data echoed correctly

### 4.4 Fuzzing

**Location**: `fuzz/stream_fuzz.zig` (new file)

```zig
const std = @import("std");
const conn_mod = @import("quic").conn;

export fn LLVMFuzzerTestOneInput(data: [*]const u8, size: usize) c_int {
    // RFC 9000 §19.8: STREAM frame fuzzing
    const allocator = std.heap.page_allocator;

    var conn = conn_mod.Connection.init(allocator, .Server) catch return 0;
    defer conn.deinit();

    const input = data[0..size];
    if (input.len < 16) return 0;

    // Extract fuzzing parameters
    const stream_id = std.mem.readIntLittle(u64, input[0..8]);
    const offset = std.mem.readIntLittle(u64, input[8..16]);
    const payload = input[16..];
    const fin = (stream_id & 0x8000_0000_0000_0000) != 0;

    // Feed to stream processing
    conn.pushStreamFrame(stream_id & 0x7FFF_FFFF_FFFF_FFFF, offset, payload, fin) catch {};

    // Try to read
    var buf: [4096]u8 = undefined;
    _ = conn.readStream(stream_id & 0x7FFF_FFFF_FFFF_FFFF, &buf) catch {};

    return 0;
}
```

**Run with AFL++ or libFuzzer**:
```bash
# Build fuzzer
zig build-lib fuzz/stream_fuzz.zig -lc -fsanitize=fuzzer --library c

# Run fuzzing
./stream_fuzz -max_len=65536 -timeout=10 fuzz_corpus/
```

**Target coverage**:
- Stream ID edge cases (0, max u64, negative when cast)
- Offset ordering (in-order, out-of-order, overlapping)
- Data sizes (0, 1, 4096, 65535, larger than buffer)
- FIN flag combinations
- Flow control boundary conditions

---

## Phase 5: Performance Benchmarking

### 5.1 Throughput Benchmarks

**Location**: `bench/stream_bench.zig` (new file)

```zig
const std = @import("std");
const builtin = @import("builtin");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== QUIC Stream Benchmarks ===\n\n", .{});

    try benchmarkSingleStreamThroughput(allocator);
    try benchmarkMultipleStreamsThroughput(allocator);
    try benchmarkFragmentation(allocator);
    try benchmarkFlowControl(allocator);
}

fn benchmarkSingleStreamThroughput(allocator: std.mem.Allocator) !void {
    const sizes = [_]usize{ 1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024 };

    std.debug.print("## Single Stream Throughput\n", .{});
    std.debug.print("| Size | Time (ms) | Throughput (MB/s) |\n", .{});
    std.debug.print("|------|-----------|-------------------|\n", .{});

    for (sizes) |size| {
        const data = try allocator.alloc(u8, size);
        defer allocator.free(data);

        // Fill with random data
        std.crypto.random.bytes(data);

        var conn = try createBenchConnection(allocator);
        defer conn.deinit();

        const start = std.time.nanoTimestamp();

        var sent: usize = 0;
        while (sent < size) {
            const n = try conn.writeStream(0, data[sent..]);
            sent += n;
        }

        const end = std.time.nanoTimestamp();
        const elapsed_ns = @as(f64, @floatFromInt(end - start));
        const elapsed_ms = elapsed_ns / 1_000_000.0;
        const throughput_mbps = (@as(f64, @floatFromInt(size)) / (1024.0 * 1024.0)) / (elapsed_ns / 1_000_000_000.0);

        std.debug.print("| {d:>5} KB | {d:8.2} | {d:17.2} |\n", .{
            size / 1024,
            elapsed_ms,
            throughput_mbps,
        });
    }
    std.debug.print("\n", .{});
}

fn benchmarkMultipleStreamsThroughput(allocator: std.mem.Allocator) !void {
    const stream_counts = [_]usize{ 1, 4, 8, 16, 32 };
    const data_per_stream: usize = 100 * 1024; // 100 KB per stream

    std.debug.print("## Multiple Concurrent Streams\n", .{});
    std.debug.print("| Streams | Time (ms) | Total Throughput (MB/s) |\n", .{});
    std.debug.print("|---------|-----------|-------------------------|\n", .{});

    for (stream_counts) |num_streams| {
        var conn = try createBenchConnection(allocator);
        defer conn.deinit();

        const total_data = num_streams * data_per_stream;

        const start = std.time.nanoTimestamp();

        // Round-robin write to each stream
        var stream_idx: usize = 0;
        var total_sent: usize = 0;
        while (total_sent < total_data) {
            const stream_id = stream_idx * 4;
            const chunk_size = @min(4096, data_per_stream);
            const chunk = try allocator.alloc(u8, chunk_size);
            defer allocator.free(chunk);

            const n = try conn.writeStream(stream_id, chunk);
            total_sent += n;

            stream_idx = (stream_idx + 1) % num_streams;
        }

        const end = std.time.nanoTimestamp();
        const elapsed_ns = @as(f64, @floatFromInt(end - start));
        const elapsed_ms = elapsed_ns / 1_000_000.0;
        const throughput_mbps = (@as(f64, @floatFromInt(total_data)) / (1024.0 * 1024.0)) / (elapsed_ns / 1_000_000_000.0);

        std.debug.print("| {d:7} | {d:9.2} | {d:23.2} |\n", .{
            num_streams,
            elapsed_ms,
            throughput_mbps,
        });
    }
    std.debug.print("\n", .{});
}
```

**Target Metrics**:
- Single stream: > 100 MB/s on localhost
- 4 concurrent streams: > 300 MB/s aggregate
- Latency: < 5ms for 1KB echo round-trip

### 5.2 Comparison Benchmarks

**Compare against reference implementations**:
```bash
# Zig vs quic-go
./bench_zig_vs_go.sh

# Zig vs aioquic (Python)
./bench_zig_vs_aioquic.sh

# Zig vs quinn (Rust)
./bench_zig_vs_quinn.sh
```

**Metrics to compare**:
- Throughput (MB/s)
- Latency (ms)
- CPU usage (%)
- Memory usage (MB)
- Connection setup time (ms)

---

## Phase 6: Documentation & Spec Compliance

### 6.1 Code Documentation

**Add doc comments to all stream-related functions**:

Example (conn.zig):
```zig
/// Accept an incoming peer-initiated stream from the queue.
///
/// This function dequeues and returns the next stream ID from `incoming_stream_queue`.
/// The stream becomes available for reading via `readStream()`.
///
/// RFC 9000 §2.1: Stream identifiers are 62-bit integers (0 to 2^62-1) that are unique
/// for all streams on a connection. The least significant bit (0x01) identifies the
/// initiator: 0 for client-initiated, 1 for server-initiated. The second least
/// significant bit (0x02) distinguishes between bidirectional (0) and unidirectional (1)
/// streams.
///
/// RFC 9000 §4.6: The maximum number of concurrent streams is controlled by the
/// MAX_STREAMS frame. This function will only return streams that have been opened by
/// the peer within the advertised limits.
///
/// Returns: The stream ID (u64) ready for use
/// Errors:
///   - `error.WouldBlock`: No streams available in the queue
///
/// See also: `hasIncomingStreams()`, `readStream()`, `writeStream()`
pub fn acceptStream(self: *Connection) !u64 {
    // ...
}
```

### 6.2 RFC Compliance Checklist

Create `RFC9000_STREAM_COMPLIANCE.md`:

```markdown
# RFC 9000 Stream Compliance Checklist

## Stream Types and Identifiers (§2.1)
- [x] Client-initiated bidirectional (ID & 0x3 == 0x0)
- [x] Server-initiated bidirectional (ID & 0x3 == 0x1)
- [x] Client-initiated unidirectional (ID & 0x3 == 0x2)
- [x] Server-initiated unidirectional (ID & 0x3 == 0x3)
- [x] Stream ID space managed separately per connection
- [ ] Stream ID reuse prohibited (verify)

## Sending Stream States (§3.1)
- [ ] Ready: Can call writeStream()
- [ ] Send: Data queued and being transmitted
- [ ] Data Sent: All data transmitted, awaiting ACKs
- [ ] Reset Sent: RESET_STREAM sent
- [ ] Reset Recvd: RESET_STREAM acknowledged

## Receiving Stream States (§3.2)
- [x] Recv: Can receive data
- [x] Size Known: FIN received, final size known
- [x] Data Recvd: All data buffered and available
- [ ] Reset Recvd: RESET_STREAM received
- [ ] Reset Read: Application consumed reset notification

## Flow Control (§4)
- [x] Per-stream flow control (MAX_STREAM_DATA)
- [x] Connection-level flow control (MAX_DATA)
- [x] Bidirectional stream limits (MAX_STREAMS bidi)
- [ ] Unidirectional stream limits (MAX_STREAMS uni)
- [x] STREAM_DATA_BLOCKED sent when blocked
- [ ] STREAMS_BLOCKED sent when limit reached

## Frame Handling
- [x] STREAM frame decoding (§19.8)
- [x] STREAM frame encoding (§19.8)
- [x] Out-of-order reassembly
- [x] Offset tracking
- [x] FIN flag handling
- [ ] RESET_STREAM frame (§19.4)
- [ ] STOP_SENDING frame (§19.5)

## Edge Cases
- [ ] Zero-length STREAM frames
- [ ] STREAM frames with only FIN
- [ ] Overlapping STREAM frames (error condition)
- [ ] Final size mismatches (error condition)
- [ ] Stream ID exceeding MAX_STREAMS
```

---

## Phase 7: Rollout & Validation

### 7.1 Incremental Deployment

1. **Phase 1 Fix Only**:
   - Apply root cause fix
   - Run existing e2e tests
   - Verify basic stream echo works

2. **Phase 2 Enhancement**:
   - Add flow control enforcement
   - Run comprehensive tests
   - Verify 100KB+ transfers work

3. **Phase 3 Optimization**:
   - Add frame scheduling
   - Run benchmarks
   - Compare with baseline

### 7.2 Validation Criteria

**Must pass before merge**:
- [ ] All unit tests pass (100% coverage of new code)
- [ ] All integration tests pass
- [ ] Comprehensive test suite passes (Go + Zig clients)
- [ ] No memory leaks (valgrind clean)
- [ ] No data races (Thread Sanitizer clean)
- [ ] Fuzzer runs 1M iterations without crash
- [ ] Throughput >= 100 MB/s single stream
- [ ] Latency <= 10ms for 1KB echo

**Spec compliance**:
- [ ] RFC 9000 §2-4 (Streams, States, Flow Control) fully implemented
- [ ] RFC 9000 §19 (Frame formats) correctly encoded/decoded
- [ ] Cross-validation with reference implementations (quic-go, aioquic, quinn)

### 7.3 Post-Merge Monitoring

**Metrics to track**:
- Stream acceptance rate
- Data throughput
- Error rates (flow control, reset, etc.)
- Memory usage per stream

**Logging additions**:
```zig
// src/quic/conn.zig
if (self.enable_metrics) {
    self.metrics.streams_accepted += 1;
    self.metrics.total_stream_bytes_rx += data.len;
    self.metrics.total_stream_bytes_tx += written;
}
```

---

## Summary & Timeline

### Phase Estimates
1. **Root Cause Analysis**: 2-4 hours (IMMEDIATE)
2. **Complete Lifecycle**: 1-2 days
3. **Frame Management**: 1 day
4. **Testing**: 1-2 days
5. **Benchmarking**: 0.5 day
6. **Documentation**: 0.5 day
7. **Rollout**: 0.5 day

**Total**: 5-8 days for complete, production-ready implementation

### Critical Path
1. Fix `isPeerInitiatedStream()` or `isStreamKnown()` logic → 2 hours
2. Verify with simple test → 1 hour
3. Run comprehensive tests → 1 hour
4. Iterate on failures → 4-8 hours

**Fastest path to working streams**: ~8 hours

### Success Criteria
- Go comprehensive test suite: 8/8 tests pass ✅
- Zig comprehensive test suite: 6/6 tests pass ✅
- No timeouts or flow control errors
- RFC 9000 compliance validated

---

## Appendix: Useful Commands

```bash
# Run specific test
zig build test --summary all -- stream_test

# Run comprehensive e2e
make e2e-comprehensive

# Run single Go test
make e2e-test-go-comprehensive

# Check for memory leaks
valgrind --leak-check=full ./zig-out/bin/quic-server

# Profile performance
perf record -g ./zig-out/bin/quic-server
perf report

# Fuzz streams
zig build fuzz-streams -- -max_total_time=3600

# Compare with baseline
./bench/compare_implementations.sh
```

## Next Immediate Action

**START WITH PHASE 1** - Debug why `incoming_stream_queue` remains empty:

1. Add temporary debug logging to track execution:
   - `pushStreamFrame` entry/exit
   - `isPeerInitiatedStream` result
   - `isStreamKnown` result
   - `queueIncomingStream` call
   - `incoming_stream_queue.append` success

2. Run simple test:
   ```bash
   make e2e-test-go 2>&1 | grep -E "pushStreamFrame|Queueing|peer_initiated" | tee debug.log
   ```

3. Analyze debug.log to find the exact failure point

4. Apply targeted fix (likely 1-5 lines of code)

5. Verify with comprehensive tests

**This plan provides a complete roadmap from immediate bug fix to production-ready, RFC-compliant, high-performance stream implementation with comprehensive testing and benchmarking.**
