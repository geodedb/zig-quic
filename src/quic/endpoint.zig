// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Endpoint skeleton with UDP send/recv (thread-safe for multi-connection handling).
//!
//! ## Threading Model (CWE-366 Mitigation)
//!
//! **IMPORTANT**: This implementation uses the following threading model:
//!
//! 1. **I/O Thread**: A single thread should call `poll()` and process incoming packets.
//!    This thread handles packet decryption, frame parsing, and state updates.
//!
//! 2. **Application Threads**: Multiple threads may safely call:
//!    - `accept()` - Accept new incoming connections
//!    - `Connection.readStream()` - Read data from streams
//!    - `Connection.writeStream()` - Write data to streams
//!    - `Connection.acceptStream()` - Accept peer-initiated streams
//!
//! **Thread Safety Implementation**:
//! - `current_io_endpoint` is `threadlocal` to support multiple endpoints in separate threads
//! - Each `Connection` has a `mu: std.Io.Mutex` protecting internal state
//! - Stream maps (`streams_rx`, `stream_txs`) are protected by the connection mutex
//! - All public stream APIs acquire the connection mutex before accessing state
//!
//! **Lock Ordering**: Always acquire endpoint lock before connection lock to prevent deadlocks.
//!
//! Implements the endpoint responsibilities from RFC 9000 (§§5–9, §14) including
//! packet processing, path validation, and PMTUD timers, plus recovery plumbing
//! from RFC 9002 (§6). TLS credential loading follows RFC 9001 §4 requirements.

const std = @import("std");
const cfg = @import("config.zig");
const lb = @import("loop_backend.zig");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const ks = @import("quic_tls");
const sig = @import("sig");
const x509 = @import("x509");
const crypto = @import("quic_crypto");
const varint = @import("quic_varint");
const token_mod = @import("quic_token");
const recovery = @import("quic_recovery");
// Import transport parameters via dedicated module to avoid duplicate root file compilation
const tp = @import("quic_transport_params");
const logger = @import("quic_logger");
const byteorder = @import("byteorder");
const utils = @import("endpoint/utils.zig");
const pto_mod = @import("endpoint/pto.zig");
const lookup = @import("endpoint/lookup.zig");
const incoming = @import("endpoint/incoming.zig");
const frame_handler = @import("endpoint/frame_handler.zig");
const handshake_integration = @import("endpoint/handshake_integration.zig");
const client_mod = @import("endpoint/client.zig");
const io_mod = @import("endpoint/io.zig");
const lifecycle_mod = @import("endpoint/lifecycle.zig");
const ep_types = @import("types");
const transport_mod = @import("endpoint/transport.zig");
const udp_transport_mod = @import("endpoint/udp_transport.zig");
const build_options = @import("quic_build_options");

// Parallel batch operations (used by recovery.zig for loss detection;
// batch crypto in endpoint.zig disabled pending pre-decrypted fast path)
// const parallel = @import("parallel");

const posix = std.posix;
const builtin = @import("builtin");

// CANARY: REQ=REQ-QUIC-HC-033; FEATURE="QUIC High-Concurrency Requests"; ASPECT=PollCycleFairnessBudget; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-26
// Do not let one endpoint poll call drain an unbounded UDP burst before
// returning to Geode's poll wrapper. The wrapper wakes parked stream readers
// after every pollWithStats() return; without this budget a high fan-out HELLO
// storm can keep the I/O thread inside Phase 4 while handlers wait on
// already-arrived stream data. Keep the cap to one UDP batch: 1024-way app
// traffic showed 100+ packet cycles monopolizing short-header processing long
// enough to push response recovery into client retry deadlines.
const client_max_packets_per_poll_cycle: usize = udp_transport_mod.UdpBatchCap;

// CANARY: REQ=REQ-QUIC-HC-142; FEATURE="QUIC High-Concurrency Requests"; ASPECT=ServerBurstReceiveBudget; STATUS=TESTED; TEST=endpoint_server_poll_budget_drains_multiple_udp_batches; OWNER=transport; UPDATED=2026-05-28
// Servers are the fan-in side of Geode's high-parallel workloads. With 1000s of
// clients, a single 64-packet drain leaves request and retransmit datagrams in
// the kernel FIFO long enough that clients enter PTO despite the query engine
// being idle. Keep clients at one batch for fast app wakeups, but let servers
// drain a bounded four-batch slice per poll call so the receive queue does not
// become the loss source during synchronized request bursts.
const server_poll_receive_batches: usize = 4;
const server_max_packets_per_poll_cycle: usize = udp_transport_mod.UdpBatchCap * server_poll_receive_batches;
const server_short_header_receive_batches: usize = server_poll_receive_batches;
const server_max_short_header_packets_per_poll_cycle: usize = udp_transport_mod.UdpBatchCap * server_short_header_receive_batches;

// CANARY: REQ=REQ-QUIC-HC-150; FEATURE="High-Concurrency Requests"; ASPECT=ServerShortHeaderCadence; STATUS=IMPL; TEST=endpoint_server_short_header_cadence_yields_after_full_slow_batch; OWNER=transport; UPDATED=2026-05-29
// Preserve the server's four-batch app receive cap for ordinary fan-in, but do
// not let one contended short-header receive cycle monopolize the embedding
// poll loop for multiple seconds. The cadence check only applies after one
// full UDP batch of short-header packets has been processed, so handshake and
// cheap request bursts keep the proven broad drain while expensive frame
// delivery yields to stream readers and timer/recovery work.
const server_short_header_cadence_min_packets: usize = udp_transport_mod.UdpBatchCap;
const server_short_header_cadence_budget_ns: u64 = 500 * std.time.ns_per_ms;

fn maxPacketsPerPollCycleForRole(role: EndpointRole) usize {
    return switch (role) {
        .Client => client_max_packets_per_poll_cycle,
        .Server => server_max_packets_per_poll_cycle,
    };
}

// CANARY: REQ=REQ-QUIC-HC-123; FEATURE="QUIC High-Concurrency Requests"; ASPECT=ShortHeaderPollBudget; STATUS=TESTED; TEST=endpoint_short_header_poll_budget; OWNER=transport; UPDATED=2026-05-28
// Application packets run decrypt, STREAM delivery, ACK/recovery, and ACK
// generation on the endpoint receive path. Keep clients at the one-batch
// fairness budget, but let servers use the bounded multi-batch drain so
// synchronized request bursts do not remain in the kernel FIFO long enough to
// enter PTO. Same-connection contention is shed inside the short-header handler.
fn maxShortHeaderPacketsPerPollCycleForRole(role: EndpointRole) usize {
    return switch (role) {
        .Client => maxPacketsPerPollCycleForRole(role),
        .Server => server_max_short_header_packets_per_poll_cycle,
    };
}

fn serverShortHeaderCadenceExpired(role: EndpointRole, elapsed_ns: u64, short_header_packets_processed: usize) bool {
    if (role != .Server) return false;
    if (short_header_packets_processed < server_short_header_cadence_min_packets) return false;
    return elapsed_ns >= server_short_header_cadence_budget_ns;
}

// CANARY: REQ=REQ-QUIC-HC-059; FEATURE="QUIC High-Concurrency Requests"; ASPECT=LongHeaderPollBudget; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-26
// Long-header Initial packets create new TLS state and are the slowest packet
// class in a fan-in storm. Cap *new Initial* processing at the same bounded
// packet-cycle budget as the rest of receive processing. The Initial and
// Handshake paths now split endpoint-map admission from per-connection crypto,
// so keeping the full cycle avoids forcing the connection-tail into PTO backoff
// while still returning to the embedding poll wrapper at a predictable cadence.
fn maxInitialPacketsPerPollCycleForRole(role: EndpointRole) usize {
    return maxPacketsPerPollCycleForRole(role);
}

// CANARY: REQ=REQ-QUIC-HC-058; FEATURE="QUIC High-Concurrency Requests"; ASPECT=PendingHandshakeRetryBudget; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-26
// Retry deferred server Handshake flights in bounded batches. Under 128+
// simultaneous clients, one poll tick can accumulate every connection in
// pending_hs_send_set; retrying all of them before returning to Geode's poll
// wrapper creates multi-second poll cycles and strands already-readable stream
// data. Keep this aligned with the UDP batch size so handshake catch-up remains
// progressive without monopolizing the poll loop.
const max_pending_hs_send_retries_per_poll_cycle: usize = udp_transport_mod.UdpBatchCap;

// CANARY: REQ=REQ-QUIC-HC-090; FEATURE="QUIC High-Concurrency Requests"; ASPECT=PtoDirtyPollBudget; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-27
// ACK processing can mark hundreds of active connections PTO-dirty at once.
// Recomputing every dirty connection in a single endpoint poll call creates
// multi-hundred-ms poll cycles that delay RX delivery for unrelated streams.
// Keep the dirty set as the durable queue and drain a bounded slice per tick.
const max_pto_dirty_recomputes_per_poll_cycle: usize = udp_transport_mod.UdpBatchCap;

// Endpoint (RFC-9000):  An entity that can participate in a QUIC connection by
//       generating, receiving, and processing QUIC packets.  There are
//       only two types of endpoints in QUIC: client and server.

// TEST-ONLY: outbound capture entry (peer + owned bytes)
const OutCaptured = struct { peer: conn_mod.SockAddr, bytes: []u8 };

// Thread-local variable to allow callbacks to access endpoint
// Must be threadlocal to support multiple endpoints in different threads
threadlocal var current_io_endpoint: ?*Endpoint = null;

// Note: Byte order conversion functions moved to utils module
inline fn portFromNetwork(value: u16) u16 {
    return utils.portFromNetwork(value);
}

inline fn portToNetwork(value: u16) u16 {
    return utils.portToNetwork(value);
}

inline fn addrToNetwork(value: u32) u32 {
    return utils.addrToNetwork(value);
}

fn nowNsMonotonic() i128 {
    // Use clock_gettime for monotonic time (Zig 0.16 removed std.time.nanoTimestamp).
    var ts: std.os.linux.timespec = undefined;
    const rc = std.os.linux.clock_gettime(.REALTIME, &ts);
    if (rc != 0) return 0;
    return @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec);
}

fn elapsedNsSince(start_ns: i128) u64 {
    const end_ns = nowNsMonotonic();
    if (end_ns <= start_ns) return 0;
    return @intCast(end_ns - start_ns);
}

fn nowMsMonotonic() i64 {
    const ms: i128 = @divTrunc(nowNsMonotonic(), std.time.ns_per_ms);
    return @as(i64, @intCast(ms));
}

/// Returns true if a timer with the given (deadline_ms, deadline_ns_extra) has
/// expired relative to (now_ms, now_ns). Sub-millisecond precision used by
/// schedulePacedNs (#158).
fn timerExpired(deadline_ms: i64, deadline_ns_extra: u32, now_ms: i64, now_ns: i128) bool {
    if (deadline_ns_extra == 0) return deadline_ms <= now_ms;
    const deadline_ns: i128 = @as(i128, deadline_ms) * std.time.ns_per_ms + @as(i128, deadline_ns_extra);
    return deadline_ns <= now_ns;
}

fn encodeVersionNegotiationPacket(
    dcid: []const u8,
    scid: []const u8,
    supported_versions: []const u32,
    out_buf: []u8,
) ![]u8 {
    const min_len = 1 + 4 + 1 + dcid.len + 1 + scid.len + (supported_versions.len * 4);
    if (out_buf.len < min_len) return error.BufferTooSmall;

    var i: usize = 0;
    // Long header with random type-specific bits.
    out_buf[i] = 0b10000000 | @as(u8, @truncate(blk: {
        var seed: [1]u8 = undefined;
        _ = std.os.linux.getrandom(&seed, seed.len, 0);
        break :blk seed[0];
    } & 0x3F));
    i += 1;
    // Version = 0x00000000 (Version Negotiation packet)
    std.mem.writeInt(u32, out_buf[i..][0..4], 0, .big);
    i += 4;
    out_buf[i] = @intCast(dcid.len);
    i += 1;
    @memcpy(out_buf[i..][0..dcid.len], dcid);
    i += dcid.len;
    out_buf[i] = @intCast(scid.len);
    i += 1;
    @memcpy(out_buf[i..][0..scid.len], scid);
    i += scid.len;
    for (supported_versions) |v| {
        std.mem.writeInt(u32, out_buf[i..][0..4], v, .big);
        i += 4;
    }
    return out_buf[0..i];
}

// Use canonical Timer and TimerKind from endpoint/types.zig (imported as ep_types)
const Timer = ep_types.Timer;
const TimerKind = ep_types.TimerKind;

fn timerBefore(a: Timer, b: Timer) bool {
    if (a.deadline_ms != b.deadline_ms) return a.deadline_ms < b.deadline_ms;
    if (a.deadline_ns_extra != b.deadline_ns_extra) return a.deadline_ns_extra < b.deadline_ns_extra;
    return a.id < b.id;
}

fn timerIndexSetExisting(timer_index: *std.AutoHashMap(u64, usize), id: u64, idx: usize) void {
    if (timer_index.getPtr(id)) |entry| {
        entry.* = idx;
    } else {
        timer_index.put(id, idx) catch |err| {
            logger.debugPrint("[ENDPOINT] timer_index put failed for id={d}: {s}\n", .{ id, @errorName(err) });
        };
    }
}

fn timerSwapIndexed(timers: *std.ArrayList(Timer), timer_index: *std.AutoHashMap(u64, usize), a: usize, b: usize) void {
    if (a == b) return;
    std.mem.swap(Timer, &timers.items[a], &timers.items[b]);
    timerIndexSetExisting(timer_index, timers.items[a].id, a);
    timerIndexSetExisting(timer_index, timers.items[b].id, b);
}

fn timerBubbleUp(timers: *std.ArrayList(Timer), timer_index: *std.AutoHashMap(u64, usize), start_idx: usize) void {
    var idx = start_idx;
    while (idx > 0) {
        const parent = (idx - 1) / 2;
        if (!timerBefore(timers.items[idx], timers.items[parent])) break;
        timerSwapIndexed(timers, timer_index, idx, parent);
        idx = parent;
    }
}

fn timerHeapifyDown(timers: *std.ArrayList(Timer), timer_index: *std.AutoHashMap(u64, usize), start_idx: usize) void {
    var idx = start_idx;
    while (true) {
        const len = timers.items.len;
        const left = 2 * idx + 1;
        const right = left + 1;
        var smallest = idx;

        if (left < len and timerBefore(timers.items[left], timers.items[smallest])) smallest = left;
        if (right < len and timerBefore(timers.items[right], timers.items[smallest])) smallest = right;
        if (smallest == idx) break;

        timerSwapIndexed(timers, timer_index, idx, smallest);
        idx = smallest;
    }
}

fn timerFixAt(timers: *std.ArrayList(Timer), timer_index: *std.AutoHashMap(u64, usize), idx: usize) void {
    if (idx >= timers.items.len) return;
    if (idx > 0) {
        const parent = (idx - 1) / 2;
        if (timerBefore(timers.items[idx], timers.items[parent])) {
            timerBubbleUp(timers, timer_index, idx);
            return;
        }
    }
    timerHeapifyDown(timers, timer_index, idx);
}

fn timerHeapifyAll(timers: *std.ArrayList(Timer), timer_index: *std.AutoHashMap(u64, usize)) void {
    if (timers.items.len <= 1) return;
    var idx = timers.items.len / 2;
    while (idx > 0) {
        idx -= 1;
        timerHeapifyDown(timers, timer_index, idx);
    }
}

fn timerPushIndexed(
    timers: *std.ArrayList(Timer),
    timer_index: *std.AutoHashMap(u64, usize),
    allocator: std.mem.Allocator,
    timer: Timer,
) !void {
    // CANARY: REQ=REQ-QUIC-HC-045; FEATURE="QUIC High-Concurrency Requests"; ASPECT=IndexedEndpointTimers; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-26
    // High fan-out handshakes constantly cancel and re-arm PTO timers. A
    // linear cancel scan over the endpoint heap turns 100s of concurrent
    // connections into poll-loop O(n^2) work. Keep an id->heap-index map so
    // cancellation stays O(log n) and packet delivery remains bounded.
    try timer_index.ensureTotalCapacity(@intCast(timer_index.count() + 1));
    try timers.append(allocator, timer);
    timer_index.putAssumeCapacityNoClobber(timer.id, timers.items.len - 1);
    timerBubbleUp(timers, timer_index, timers.items.len - 1);
}

fn timerRemoveAtIndexed(
    timers: *std.ArrayList(Timer),
    timer_index: *std.AutoHashMap(u64, usize),
    idx: usize,
) Timer {
    const removed = timers.items[idx];
    _ = timer_index.remove(removed.id);

    const last_idx = timers.items.len - 1;
    if (idx == last_idx) {
        _ = timers.pop();
        return removed;
    }

    timers.items[idx] = timers.items[last_idx];
    _ = timers.pop();
    timerIndexSetExisting(timer_index, timers.items[idx].id, idx);
    timerFixAt(timers, timer_index, idx);
    return removed;
}

/// Observability for poll loops (number of datagrams drained per iteration).
pub const PollStats = struct {
    packets_processed: usize = 0,
    // CANARY: REQ=REQ-QUIC-HC-092; FEATURE="QUIC High-Concurrency Requests"; ASPECT=PollPhaseTiming; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-27
    transport_poll_ns: u64 = 0,
    recv_process_ns: u64 = 0,
    // CANARY: REQ=REQ-QUIC-HC-094; FEATURE="QUIC High-Concurrency Requests"; ASPECT=RecvKindTiming; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-27
    recv_short_header_ns: u64 = 0,
    recv_initial_ns: u64 = 0,
    recv_handshake_ns: u64 = 0,
    recv_fallback_ns: u64 = 0,
    recv_short_endpoint_map_ns: u64 = 0,
    recv_short_rx_serial_wait_ns: u64 = 0,
    recv_short_conn_lock_wait_ns: u64 = 0,
    recv_short_decrypt_ns: u64 = 0,
    recv_short_frame_process_ns: u64 = 0,
    recv_short_ack_send_ns: u64 = 0,
    pending_hs_send_ns: u64 = 0,
    timer_process_ns: u64 = 0,
    pto_dirty_ns: u64 = 0,
};

/// Hash key combining peer address + destination CID for connection lookup.
///
/// RFC 9000 §5.1 mandates that servers route packets using tuple + DCID. We use
/// this composite hash so multipath/path validation still find the right entry.
pub const Key = ep_types.Key;

// CANARY: REQ=REQ-QUIC-HC-117; FEATURE="High-Concurrency Requests"; ASPECT=RoleSizedRouteCache; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-27
// Server endpoints need enough direct-mapped short-header route slots for
// tens of thousands of active CIDs without constant endpoint-map fallback.
// Client endpoints usually carry one connection and are often created by the
// thousands in fan-out tests, so keep their cache small to avoid per-client
// memory blow-up.
const short_header_route_cache_client_slots: usize = 256;
const short_header_route_cache_server_slots: usize = 65536;

const ShortHeaderRouteCacheSlot = struct {
    mu: std.Io.Mutex = std.Io.Mutex.init,
    peer_hash: u64 = 0,
    dcid_hash: u64 = 0,
    dcid_len: u8 = 0,
    conn: ?*conn_mod.Connection = null,
};

const CachedShortHeaderRoute = struct {
    conn: *conn_mod.Connection,
    lookup_result: lookup.LookupResult,
};

// Note: Utility functions moved to utils module
// Kept as inline wrappers for backward compatibility
inline fn hashBytes(b: []const u8) u64 {
    return utils.hashBytes(b);
}

inline fn routeCacheIndex(peer_hash: u64, dcid_hash: u64, slot_count: usize) usize {
    const mixed = peer_hash ^ (dcid_hash *% 0x9E37_79B9_7F4A_7C15);
    return @intCast(mixed & @as(u64, @intCast(slot_count - 1)));
}

inline fn shortHeaderRouteCacheSlotCount(role: EndpointRole) usize {
    return switch (role) {
        .Server => short_header_route_cache_server_slots,
        .Client => short_header_route_cache_client_slots,
    };
}

fn envFlag(name: [*:0]const u8) bool {
    const raw = std.c.getenv(name) orelse return false;
    const value = std.mem.span(raw);
    if (value.len == 0) return false;
    if (std.mem.eql(u8, value, "0")) return false;
    if (std.ascii.eqlIgnoreCase(value, "false")) return false;
    if (std.ascii.eqlIgnoreCase(value, "no")) return false;
    if (std.ascii.eqlIgnoreCase(value, "off")) return false;
    return true;
}

fn shortHeaderDiagnosticsEnabled() bool {
    return envFlag("GEODE_QUIC_SHORT_HEADER_DIAGNOSTICS");
}

fn peerPort(peer: conn_mod.SockAddr) u16 {
    return switch (peer.storage.family) {
        posix.AF.INET => blk: {
            const sin: *const posix.sockaddr.in = @ptrCast(@alignCast(&peer.storage));
            break :blk std.mem.bigToNative(u16, sin.port);
        },
        posix.AF.INET6 => blk: {
            const sin6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(&peer.storage));
            break :blk std.mem.bigToNative(u16, sin6.port);
        },
        else => 0,
    };
}

fn classifyLongHeaderPacket(bytes: []const u8) ?packet.LongHeaderPacketType {
    if (bytes.len < 5 or (bytes[0] & 0x80) == 0) return null;
    const version: u32 = (@as(u32, bytes[1]) << 24) |
        (@as(u32, bytes[2]) << 16) |
        (@as(u32, bytes[3]) << 8) |
        @as(u32, bytes[4]);
    if (version == 0) return null;
    return packet.longHeaderPacketType(version, bytes[0]);
}

fn parseLongHeaderVersion(bytes: []const u8) ?u32 {
    if (bytes.len < 5 or (bytes[0] & 0x80) == 0) return null;
    return (@as(u32, bytes[1]) << 24) |
        (@as(u32, bytes[2]) << 16) |
        (@as(u32, bytes[3]) << 8) |
        @as(u32, bytes[4]);
}

fn longHeaderPacketLength(bytes: []const u8, version: u32) ?usize {
    if (bytes.len < 7 or version == 0) return null;
    const first = bytes[0];
    if (packet.longHeaderPacketType(version, first) == .Retry) return null;

    const dcid_len: usize = bytes[5];
    if (dcid_len > 20) return null;
    if (bytes.len < 6 + dcid_len + 1) return null;

    const scid_len: usize = bytes[6 + dcid_len];
    if (scid_len > 20) return null;
    if (bytes.len < 7 + dcid_len + scid_len) return null;

    var offset: usize = 7 + dcid_len + scid_len;
    if (packet.longHeaderPacketType(version, first) == .Initial) {
        if (bytes.len <= offset) return null;
        const token_len = varint.decode(bytes[offset..]) catch return null;
        offset += token_len.n;
        const token_len_usize: usize = @intCast(token_len.value);
        if (bytes.len < offset + token_len_usize) return null;
        offset += token_len_usize;
    }

    if (bytes.len <= offset) return null;
    const len_result = varint.decode(bytes[offset..]) catch return null;
    offset += len_result.n;
    const total_len = offset + @as(usize, @intCast(len_result.value));
    if (total_len > bytes.len) return null;
    return total_len;
}

inline fn normalizeAddr(sa: *const posix.sockaddr.storage, len: u32) conn_mod.SockAddr {
    return utils.normalizeAddr(sa, len);
}

pub fn hashSockaddr(sa: *const posix.sockaddr.storage, len: u32) u64 {
    return utils.hashSockaddr(sa, len);
}

/// Endpoint role enum
pub const EndpointRole = enum {
    Client,
    Server,
};

/// single bound socket. Owns all live connections and drives send/recv plus PTO/PMTUD timers.
///
/// Covers the UDP abstraction and anti-amplification logic described in RFC 9000
/// §8, manages Retry/NEW_TOKEN (via config) per §8.1, and orchestrates timers for
/// loss recovery as recommended by RFC 9002 §6.
pub const Endpoint = struct {

    // GAP-0200: Fine-grained locking for concurrent poll + handler throughput.
    //
    // mu: Primary lock protecting connection map (conns), accepted queue, retired list.
    //     Also used by processIncomingDatagram which mutates connection state.
    //     Lock ordering: endpoint.mu -> connection.mu (never reverse)
    mu: std.Io.Mutex = std.Io.Mutex.init,

    // timer_mu: Separate lock for timer queue and next_timer_id.
    //     Decoupled from mu so timer scheduling (senderPaced, scheduleConnPto)
    //     doesn't contend with poll's packet processing or connection lookup.
    timer_mu: std.Io.Mutex = std.Io.Mutex.init,

    // Transport abstraction (Phase 8c: required, wraps UDP or loopback)
    // All I/O operations go through this transport interface
    transport: transport_mod.Transport,

    // Owned UDP transport (heap-allocated, null if using custom transport)
    owned_udp_transport: ?*udp_transport_mod.UdpTransport = null,

    // Event loop backend (os specific)
    loop_backend: lb.LoopBackend,

    // Memory allocator for endpoint resources
    allocator: std.mem.Allocator,

    // Timer management for the endpoint (protected by timer_mu)
    timers: std.ArrayList(Timer),
    timer_index: std.AutoHashMap(u64, usize),

    // Connection Management Map (protected by mu)
    conns: std.AutoHashMap(Key, *conn_mod.Connection),
    // CANARY: REQ=REQ-QUIC-HC-098; FEATURE="QUIC High-Concurrency Requests"; ASPECT=ShortHeaderRouteCache; STATUS=IMPL; TEST=test-quic-high-concurrency-e2e; OWNER=transport; UPDATED=2026-05-27
    //
    // Established 1-RTT packets dominate high-fanout workloads. Cache resolved
    // peer+DCID routes behind sharded slot locks so steady-state short-header
    // receive paths do not all serialize on the endpoint connection-map mutex.
    short_header_route_cache: []ShortHeaderRouteCacheSlot,
    // Detailed short-header subphase timings are diagnostic-only. Keep them
    // opt-in so high-throughput ReleaseSafe runs do not pay multiple
    // clock_gettime calls per packet.
    short_header_timing_enabled: bool = false,

    // PTO-dirty tracking (#182 closure). `pto_dirty_count` is an atomic
    // counter incremented on every false→true transition of `Connection.pto_dirty`;
    // when zero, the poll loop skips the dirty scan entirely. The hash set
    // mirrors which connections are dirty so the poll loop can iterate only
    // that subset (O(dirty)) under the dedicated leaf mutex `pto_dirty_mu`,
    // avoiding the existing endpoint.mu -> conn.mu lock order.
    pto_dirty_set: std.AutoHashMap(*conn_mod.Connection, void),
    pto_dirty_mu: std.Io.Mutex = std.Io.Mutex.init,
    pto_lifetime_mu: std.Io.Mutex = std.Io.Mutex.init,
    pto_dirty_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    // Server-side deferred Handshake packet sends. This replaces the old
    // poll-time full connection-map scan with an O(pending) set so clean polls
    // stay bounded at high connection counts.
    pending_hs_send_set: std.AutoHashMap(*conn_mod.Connection, void),
    pending_hs_send_mu: std.Io.Mutex = std.Io.Mutex.init,
    pending_hs_send_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    // Closed-connection tracking. Connection.markClosed() notifies this set so
    // pruneClosed() is O(closed) instead of scanning the full connection map on
    // every poll tick.
    closed_conn_set: std.AutoHashMap(*conn_mod.Connection, void),
    closed_conn_mu: std.Io.Mutex = std.Io.Mutex.init,
    closed_conn_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    // Next timer identifier for scheduleTimer (protected by timer_mu)
    next_timer_id: u64 = 1,
    // Config copy
    cfg: cfg.QuicConfig,
    // Accept queue for server (protected by mu)
    // GAP-0200: Thread-safe accept queue - poll() adds, accept() removes
    accepted: std.ArrayList(*conn_mod.Connection),
    // CANARY: REQ=REQ-QUIC-HC-106; FEATURE="High-Concurrency Connection Admission"; ASPECT=AcceptedQueueFutexWake; STATUS=TESTED; TEST=test_quic_condition_timedwait_cadence; OWNER=transport; UPDATED=2026-05-27
    // Producers bump this generation after enqueueing an accepted connection
    // so waitForAccepted() can park on a futex instead of a fixed 5ms
    // nanosleep cadence during high fan-out handshakes.
    accepted_generation: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    // Condition variable signaled when a new connection is pushed to the
    // accepted queue.  Allows callers to block efficiently in accept() instead
    // of busy-polling.  Protected by mu (waiters must hold mu).
    accept_cv: std.Io.Condition = .init,
    // TEST-ONLY: outbound capture ring (peer + owned bytes)
    captures: std.ArrayList(OutCaptured),
    // TEST-ONLY: runtime flag to enable outbound capture in tests
    test_capture_enabled: bool = false,
    // Retired (closed) connections removed from maps & timers but not yet destroyed.
    // They stay here until explicit api.destroy() or endpoint.deinit(), allowing external
    // code (e.g., server CLI loop) holding an opaque pointer to observe closed state
    // without risking use-after-free. (protected by mu)
    retired: std.ArrayList(*conn_mod.Connection),
    // Epoll file descriptor for Linux
    epoll_fd: ?posix.fd_t = null,
    // Endpoint role (Client or Server)
    role: EndpointRole,

    // Generated token secret for Retry/NEW_TOKEN if user doesn't provide one.
    // 32 bytes of cryptographically random data generated at endpoint init.
    // This replaces the hardcoded fallback to prevent predictable tokens.
    generated_token_secret: [32]u8 = undefined,

    // Server-side 0-RTT anti-replay cache (RFC 8446 S8, RFC 9001 S9.2).
    // Heap-allocated when role == Server and config.zero_rtt_anti_replay == true.
    // Shared across all connections on this endpoint; connections hold a pointer
    // to this cache so the endpoint must outlive its connections.
    // null when disabled or when the endpoint is a client.
    anti_replay_cache: ?*conn_mod.AntiReplayCache = null,

    // Note: mu_owner removed — timer ops now use separate timer_mu so
    // re-entrancy tracking is no longer needed.

    /// Initialize a UDP endpoint bound to bind_addr (e.g., "127.0.0.1:0").
    ///
    /// Phase 8c: Now uses UdpTransport internally for all socket operations.
    /// The endpoint creates a UDP socket via the transport abstraction layer.
    pub fn init(alloc: std.mem.Allocator, bind_addr: []const u8, cfgp: *const cfg.QuicConfig) !Endpoint {
        // Create UDP transport (handles socket creation, binding, configuration)
        // IMPORTANT: Must heap-allocate because Transport stores a pointer to it
        const udp = try alloc.create(udp_transport_mod.UdpTransport);
        errdefer alloc.destroy(udp);

        udp.* = try udp_transport_mod.UdpTransport.init(bind_addr);
        errdefer udp.deinit();

        // Convert to generic transport interface
        const transport = udp.asTransport();

        // Determine role from config: servers have TLS certificates configured.
        // This replaces the previous port-number heuristic (checking :4433/:443)
        // which was fragile and incorrect for non-standard ports.
        const is_server = cfgp.cert_path != null or cfgp.inline_server_cert_der != null;
        const endpoint_role = if (is_server) EndpointRole.Server else EndpointRole.Client;

        logger.debugPrint("Endpoint role determined as: {any}\n", .{endpoint_role});

        // Generate cryptographically random token secret if not provided in config.
        // This prevents using a hardcoded fallback which would be predictable.
        var generated_secret: [32]u8 = undefined;
        _ = std.os.linux.getrandom(&generated_secret, generated_secret.len, 0);

        // Initialize 0-RTT anti-replay cache for server endpoints (RFC 8446 S8, RFC 9001 S9.2).
        // Window: 10 seconds, max entries: 10000 -- reasonable defaults for production use.
        const arc: ?*conn_mod.AntiReplayCache = if (is_server and cfgp.zero_rtt_anti_replay) blk: {
            const cache = try alloc.create(conn_mod.AntiReplayCache);
            cache.* = conn_mod.AntiReplayCache.init(alloc, 10_000, 10_000_000_000);
            break :blk cache;
        } else null;
        errdefer if (arc) |c| {
            c.deinit();
            alloc.destroy(c);
        };

        const short_route_cache = try alloc.alloc(ShortHeaderRouteCacheSlot, shortHeaderRouteCacheSlotCount(endpoint_role));
        errdefer alloc.free(short_route_cache);
        for (short_route_cache) |*slot| slot.* = .{};

        return Endpoint{
            .transport = transport,
            .owned_udp_transport = udp,
            .loop_backend = lb.defaultLoopBackend(),
            .allocator = alloc,
            .timers = .empty,
            .timer_index = std.AutoHashMap(u64, usize).init(alloc),
            .conns = std.AutoHashMap(Key, *conn_mod.Connection).init(alloc),
            .short_header_route_cache = short_route_cache,
            .short_header_timing_enabled = envFlag("GEODE_QUIC_SHORT_HEADER_TIMING"),
            .pto_dirty_set = std.AutoHashMap(*conn_mod.Connection, void).init(alloc),
            .pending_hs_send_set = std.AutoHashMap(*conn_mod.Connection, void).init(alloc),
            .closed_conn_set = std.AutoHashMap(*conn_mod.Connection, void).init(alloc),
            .next_timer_id = 1,
            .cfg = cfgp.*,
            .accepted = .empty,
            .captures = .empty,
            .test_capture_enabled = false,
            .retired = .empty,
            .epoll_fd = null, // Not used with transport abstraction
            .role = endpoint_role,
            .generated_token_secret = generated_secret,
            .anti_replay_cache = arc,
        };
    }

    /// Initialize endpoint with custom transport (Phase 8c: for loopback testing).
    /// This method allows creating an endpoint with a pluggable transport backend
    /// (e.g., loopback for testing) instead of a real UDP socket.
    pub fn initWithTransport(
        alloc: *std.mem.Allocator,
        transport: transport_mod.Transport,
        cfgp: *const cfg.QuicConfig,
        endpoint_role: EndpointRole,
    ) !Endpoint {
        // Role now passed as parameter instead of hardcoded

        // Generate cryptographically random token secret if not provided in config.
        var generated_secret: [32]u8 = undefined;
        _ = std.os.linux.getrandom(&generated_secret, generated_secret.len, 0);

        // Initialize 0-RTT anti-replay cache for server endpoints (RFC 8446 S8, RFC 9001 S9.2).
        const is_server = (endpoint_role == .Server);
        const arc: ?*conn_mod.AntiReplayCache = if (is_server and cfgp.zero_rtt_anti_replay) blk: {
            const cache = try alloc.create(conn_mod.AntiReplayCache);
            cache.* = conn_mod.AntiReplayCache.init(alloc.*, 10_000, 10_000_000_000);
            break :blk cache;
        } else null;
        errdefer if (arc) |c| {
            c.deinit();
            alloc.destroy(c);
        };

        const short_route_cache = try alloc.alloc(ShortHeaderRouteCacheSlot, shortHeaderRouteCacheSlotCount(endpoint_role));
        errdefer alloc.free(short_route_cache);
        for (short_route_cache) |*slot| slot.* = .{};

        return Endpoint{
            .transport = transport,
            .loop_backend = lb.defaultLoopBackend(),
            .allocator = alloc.*,
            .timers = .empty,
            .timer_index = std.AutoHashMap(u64, usize).init(alloc.*),
            .conns = std.AutoHashMap(Key, *conn_mod.Connection).init(alloc.*),
            .short_header_route_cache = short_route_cache,
            .short_header_timing_enabled = envFlag("GEODE_QUIC_SHORT_HEADER_TIMING"),
            .pto_dirty_set = std.AutoHashMap(*conn_mod.Connection, void).init(alloc.*),
            .pending_hs_send_set = std.AutoHashMap(*conn_mod.Connection, void).init(alloc.*),
            .closed_conn_set = std.AutoHashMap(*conn_mod.Connection, void).init(alloc.*),
            .next_timer_id = 1,
            .cfg = cfgp.*,
            .accepted = .empty,
            .captures = .empty,
            .test_capture_enabled = false,
            .retired = .empty,
            .epoll_fd = null, // No epoll with transport abstraction
            .role = endpoint_role,
            .generated_token_secret = generated_secret,
            .anti_replay_cache = arc,
        };
    }

    /// Deinitialize endpoint and free all associated connection state.
    pub fn deinit(self: *Endpoint) void {
        // Skip pruneClosed() during deinit — connection pointers in the map
        // may be in an inconsistent state (partially torn down by transport
        // layer cleanup). Instead, destroy all connections directly below.
        // Instrumentation: list any remaining connection pointers (map values) before cleanup
        if (builtin.mode == .Debug) {
            var unique = std.AutoHashMap(*conn_mod.Connection, usize).init(self.allocator);
            defer unique.deinit();
            var cit = self.conns.iterator();
            while (cit.next()) |e| {
                const c = e.value_ptr.*;
                const idx = unique.get(c) orelse 0;
                _ = unique.put(c, idx + 1) catch |err| {
                    logger.debugPrint("endpoint.deinit: unique.put failed (OOM): {}\n", .{err});
                };
            }
            if (unique.count() > 0) {
                logger.debugPrint("endpoint.deinit: {d} unique conn(s) still referenced by map; dumping counts\n", .{unique.count()});
                var uit = unique.iterator();
                while (uit.next()) |ve| {
                    logger.debugPrint("  conn ptr={*} ref_count={d}\n", .{ ve.key_ptr.*, ve.value_ptr.* });
                }
                // Also dump timers referencing a connection
                var ti: usize = 0;
                var timer_conn_refs: usize = 0;
                while (ti < self.timers.items.len) : (ti += 1) {
                    const t = self.timers.items[ti];
                    if (t.conn) |tc| {
                        timer_conn_refs += 1;
                        logger.debugPrint("  timer id={d} kind={any} conn={*}\n", .{ t.id, t.kind, tc });
                    }
                }
                if (timer_conn_refs > 0) logger.debugPrint("  timers referencing connections: {d}\n", .{timer_conn_refs});
            }
        }
        // Free captured payloads
        var i: usize = 0;
        while (i < self.captures.items.len) : (i += 1) {
            const cap = self.captures.items[i];
            self.allocator.free(cap.bytes);
        }
        self.captures.deinit(self.allocator);
        // Free any pending paced payloads in timers
        var j: usize = 0;
        while (j < self.timers.items.len) : (j += 1) {
            const t = self.timers.items[j];
            if (t.paced) {
                if (t.payload) |p| self.allocator.free(p);
            }
        }
        // Collect unique connection pointers from map, then clear the map
        // before destroying any connections. This avoids iterating the map
        // while connection state may be inconsistent.
        var to_destroy: std.ArrayList(*conn_mod.Connection) = .empty;
        defer to_destroy.deinit(self.allocator);
        {
            var it = self.conns.iterator();
            while (it.next()) |e| {
                const c = e.value_ptr.*;
                // Check if already collected (multiple CIDs may map to same conn)
                var dup = false;
                for (to_destroy.items) |existing| {
                    if (existing == c) {
                        dup = true;
                        break;
                    }
                }
                if (!dup) to_destroy.append(self.allocator, c) catch {};
            }
        }
        // Also collect retired connections
        for (self.retired.items) |c| {
            var dup = false;
            for (to_destroy.items) |existing| {
                if (existing == c) {
                    dup = true;
                    break;
                }
            }
            if (!dup) to_destroy.append(self.allocator, c) catch {};
        }
        // Destroy collected connections. Connection.deinit() has a deinit_called
        // guard so double-deinit is safe (no-op on second call). This ensures
        // TLS buffers, stream arrays, and other connection state are freed even
        // when the transport layer didn't drain them before endpoint shutdown.
        for (to_destroy.items) |c| {
            c.deinit();
            self.allocator.destroy(c);
        }
        self.retired.deinit(self.allocator);
        self.allocator.free(self.short_header_route_cache);
        self.conns.deinit();
        self.pto_dirty_set.deinit();
        self.pending_hs_send_set.deinit();
        self.closed_conn_set.deinit();
        self.accepted.deinit(self.allocator);
        self.timer_index.deinit();
        self.timers.deinit(self.allocator);

        // Destroy the anti-replay cache (must happen after all connections are destroyed
        // because connections hold a pointer to this cache).
        if (self.anti_replay_cache) |cache| {
            cache.deinit();
            self.allocator.destroy(cache);
        }

        // Phase 8c: Close transport (which closes underlying socket)
        self.transport.close();

        // Free heap-allocated UDP transport if we own it
        if (self.owned_udp_transport) |udp| {
            self.allocator.destroy(udp);
        }
    }

    /// Expire due timers without blocking on I/O (test helper).
    pub fn flushTimers(self: *Endpoint) void {
        self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        self.timer_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer {
            self.timer_mu.unlock(std.Io.Threaded.global_single_threaded.io());
            self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
        }
        self.processExpiredTimers(nowMsMonotonic());
    }

    /// Clear all captured outbound packets (test helper).
    pub fn captureClear(self: *Endpoint) void {
        var i: usize = 0;
        while (i < self.captures.items.len) : (i += 1) self.allocator.free(self.captures.items[i].bytes);
        self.captures.clearRetainingCapacity();
    }
    /// Return number of captured outbound packets.
    pub fn captureLen(self: *Endpoint) usize {
        return self.captures.items.len;
    }
    /// Pop most recent captured outbound packet if present.
    pub fn capturePop(self: *Endpoint) ?OutCaptured {
        if (self.captures.items.len == 0) return null;
        // PERF-P2b: O(1) removal — capture order is not significant.
        return self.captures.swapRemove(0);
    }

    /// Internal: convert socket_t to isize for Connection.sock_fd storage.
    fn sockToIsize(fd: posix.socket_t) isize {
        if (builtin.target.os.tag == .windows) {
            return @as(isize, @intCast(@intFromPtr(fd)));
        } else {
            return @as(isize, @intCast(fd));
        }
    }

    /// Send UDP datagram to peer (capturing if enabled).
    /// Send UDP datagram to peer. Supports test capture mode.
    /// Phase 8a: Uses transport abstraction if available, otherwise delegates to io_mod.
    /// Send UDP datagram to peer via transport abstraction.
    /// Phase 8c: Always uses transport (no fallback to sock_fd).
    pub fn sendTo(self: *Endpoint, peer: conn_mod.SockAddr, data: []const u8) !usize {
        // Test capture: make owned copy and enqueue without sending
        if (self.test_capture_enabled) {
            const owned = try self.allocator.alloc(u8, data.len);
            @memcpy(owned, data);
            _ = self.captures.append(self.allocator, .{ .peer = peer, .bytes = owned }) catch |err| {
                logger.warn("test capture append failed (OOM): {s}", .{@errorName(err)});
            };
        }

        // Phase 8c: Always use transport directly for sends (single-threaded event loop)
        return try self.transport.send(peer, data);
    }

    /// Receive UDP datagram via transport abstraction (non-blocking).
    /// Phase 8c: Always uses transport (no fallback to sock_fd).
    pub fn recvFrom(self: *Endpoint, buf: []u8) !struct { n: usize, peer: conn_mod.SockAddr } {
        // Phase 8c: Always use transport (transport is now required, not optional)
        const result = try self.transport.recv(buf);
        return .{ .n = result.n, .peer = result.peer };
    }

    /// Accept a server connection from initial datagram's peer address.
    /// Phase 8c: sock_fd set to -1 (I/O goes through endpoint transport)
    pub fn acceptFrom(self: *Endpoint, peer: conn_mod.SockAddr) conn_mod.Connection {
        _ = self; // unused
        return .{ .id = 0, .role = .Server, .sock_fd = -1, .peer = peer, .tls_inbox = .empty };
    }

    /// Enqueue accepted server connection for accept().
    /// GAP-0200: Thread-safe - acquires endpoint mutex
    fn pushAccepted(self: *Endpoint, c: *conn_mod.Connection) void {
        var enqueued = false;
        self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        // OOM here drops the connection from the accept queue -- it will
        // never be returned to the application.  Log so the operator can
        // detect pressure on the allocator.
        self.accepted.append(self.allocator, c) catch |err| {
            self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
            logger.debugPrint("[ENDPOINT] pushAccepted failed: {s} -- connection lost\n", .{@errorName(err)});
            return;
        };
        enqueued = true;
        // Wake any thread blocked in waitForAccepted().
        self.accept_cv.signal(std.Io.Threaded.global_single_threaded.io());
        self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
        if (enqueued) self.wakeAcceptedWaiter();
    }

    /// Pop next accepted server-side connection if available.
    /// GAP-0200: Thread-safe - acquires endpoint mutex.
    pub fn popAccepted(self: *Endpoint) ?*conn_mod.Connection {
        self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
        if (self.accepted.items.len == 0) return null;
        // CANARY: REQ=REQ-QUIC-HC-107; FEATURE="High-Concurrency Connection Admission"; ASPECT=AcceptedQueueO1Pop; STATUS=TESTED; TEST=test_quic_condition_timedwait_cadence; OWNER=transport; UPDATED=2026-05-27
        // Accept order is not a protocol contract. Avoid O(n) front removal
        // under the endpoint mutex when hundreds of completed handshakes enter
        // the accepted queue at once.
        return self.accepted.swapRemove(0);
    }

    /// Block until a connection is available or timeout expires.
    /// Returns the accepted connection, or null on timeout.
    /// The caller must ensure poll() is being called on another thread (or
    /// interleaved) so that incoming packets are processed and connections
    /// actually reach the accepted queue.
    pub fn waitForAccepted(self: *Endpoint, timeout_ms: u32) ?*conn_mod.Connection {
        const start_ns = nowNsMonotonic();
        const timeout_ns: u64 = @as(u64, timeout_ms) * std.time.ns_per_ms;
        const deadline_ns = start_ns + @as(i128, @intCast(timeout_ns));
        const io = std.Io.Threaded.global_single_threaded.io();

        while (true) {
            self.mu.lockUncancelable(io);
            if (self.accepted.items.len > 0) {
                const conn = self.accepted.swapRemove(0);
                self.mu.unlock(io);
                return conn;
            }
            const observed = self.accepted_generation.load(.acquire);
            self.mu.unlock(io);

            const now_ns = nowNsMonotonic();
            if (now_ns >= deadline_ns) return null;
            const remaining_ns: u64 = @intCast(deadline_ns - now_ns);
            const timeout: std.Io.Timeout = .{ .duration = .{
                .raw = std.Io.Duration.fromNanoseconds(@intCast(remaining_ns)),
                .clock = .awake,
            } };
            io.futexWaitTimeout(u32, &self.accepted_generation.raw, observed, timeout) catch |err| switch (err) {
                error.Canceled => return null,
            };
        }
    }

    fn wakeAcceptedWaiter(self: *Endpoint) void {
        _ = self.accepted_generation.fetchAdd(1, .release);
        std.Io.Threaded.global_single_threaded.io().futexWake(u32, &self.accepted_generation.raw, 1);
    }

    // CANARY: REQ=REQ-QUIC-HC-063; FEATURE="QUIC High-Concurrency Requests"; ASPECT=DeferredServerAccept; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-26
    fn maybeQueueDeferredAccepted(self: *Endpoint, c: *conn_mod.Connection) void {
        if (self.role != .Server or !self.cfg.defer_accept_until_stream) return;

        var enqueued = false;
        self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());

        if (c.closed or c.role != .Server) {
            self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
            return;
        }

        var should_queue = false;
        c.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        if (!c.accepted_enqueued and
            c.app_rx_keys != null and
            c.app_tx_keys != null and
            c.incoming_stream_queue.items.len > 0)
        {
            c.accepted_enqueued = true;
            should_queue = true;
        }
        c.mu.unlock(std.Io.Threaded.global_single_threaded.io());

        if (!should_queue) {
            self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
            return;
        }

        self.accepted.append(self.allocator, c) catch |err| {
            c.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
            c.accepted_enqueued = false;
            c.mu.unlock(std.Io.Threaded.global_single_threaded.io());
            self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
            logger.debugPrint("[ENDPOINT] deferred accept append failed: {s}\n", .{@errorName(err)});
            return;
        };
        enqueued = true;
        self.accept_cv.signal(std.Io.Threaded.global_single_threaded.io());
        self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
        if (enqueued) self.wakeAcceptedWaiter();
    }

    /// Inject inbound datagram into receive path (test helper, no ECN).
    pub fn testInject(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8) void {
        self.processIncomingDatagram(peer, bytes, null);
    }

    /// Inject inbound datagram with explicit ECN bits (test helper).
    pub fn testInjectWithEcn(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, ecn_bits: u8) void {
        self.processIncomingDatagram(peer, bytes, ecn_bits);
    }

    // CANARY: REQ=REQ-QUIC-HC-065; FEATURE="QUIC High-Concurrency Requests"; ASPECT=InitialAdmissionLockSplit; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-26
    fn processInitialDatagramConcurrent(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, version: u32) void {
        if (bytes.len == 0 or (bytes[0] & 0x80) == 0) return;

        const norm_peer = normalizeAddr(&peer.storage, peer.len);
        const header = incoming.parseInitialHeader(bytes) catch return;
        var token_offset = header.offset;
        const tok_len_dec = varint.decode(bytes[token_offset..]) catch return;
        token_offset += tok_len_dec.n;
        const tok_len_usize = @as(usize, @intCast(@min(tok_len_dec.value, bytes.len - token_offset)));
        if (token_offset + tok_len_usize > bytes.len) return;
        const token_bytes = bytes[token_offset .. token_offset + tok_len_usize];

        current_io_endpoint = self;
        defer current_io_endpoint = null;

        const role_converted = @as(ep_types.EndpointRole, @enumFromInt(@intFromEnum(self.role)));
        var rx_ctx = incoming.RxContext{
            .allocator = &self.allocator,
            .conns = &self.conns,
            .accepted = &self.accepted,
            .cfg = &self.cfg,
            .send_fn = struct {
                fn send(peer_addr: conn_mod.SockAddr, data: []const u8) anyerror!usize {
                    const ep = current_io_endpoint.?;
                    return ep.sendTo(peer_addr, data);
                }
            }.send,
            .schedule_timer_fn = struct {
                fn schedule(conn_arg: *conn_mod.Connection, kind: ep_types.TimerKind, delay_ms: u32) anyerror!u64 {
                    const ep = current_io_endpoint.?;
                    return ep.scheduleConnPto(conn_arg, kind, delay_ms);
                }
            }.schedule,
            .send_initial_probe_fn = struct {
                fn probe(conn_arg: *conn_mod.Connection) anyerror!void {
                    const ep = current_io_endpoint.?;
                    return ep.clientSendInitialProbe(conn_arg);
                }
            }.probe,
            .setup_sender_fn = struct {
                fn setup(conn_arg: *conn_mod.Connection) void {
                    const ep = current_io_endpoint.?;
                    conn_arg.setSender(@ptrCast(ep), senderPaced);
                    conn_arg.setPtoDirtyNotifier(@ptrCast(ep), notifyPtoDirty);
                    conn_arg.setCloseNotifier(@ptrCast(ep), notifyConnectionClosed);
                }
            }.setup,
            .mark_pending_hs_send_fn = struct {
                fn mark(conn_arg: *conn_mod.Connection) void {
                    const ep = current_io_endpoint.?;
                    ep.markPendingHandshakeSend(conn_arg);
                }
            }.mark,
            .test_capture_enabled = self.test_capture_enabled,
            .endpoint_role = role_converted,
            .endpoint_ctx = self,
            .generated_token_secret = &self.generated_token_secret,
            .max_connections = self.cfg.max_connections,
            .anti_replay_cache = self.anti_replay_cache,
        };

        const conn = blk: {
            self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
            defer self.mu.unlock(std.Io.Threaded.global_single_threaded.io());

            const prepared = incoming.prepareInitialConnection(&rx_ctx, norm_peer, header, token_bytes, version);
            switch (prepared) {
                .ready => |c| {
                    if (!c.acquireEndpointRxRef()) return;
                    break :blk c;
                },
                .consumed => return,
            }
        };
        defer conn.releaseEndpointRxRef();

        conn.endpoint_rx_serial_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer conn.endpoint_rx_serial_mu.unlock(std.Io.Threaded.global_single_threaded.io());

        incoming.processInitialResolved(&rx_ctx, norm_peer, bytes, version, header, token_bytes, conn);
    }

    // CANARY: REQ=REQ-QUIC-HC-066; FEATURE="QUIC High-Concurrency Requests"; ASPECT=HandshakeLockSplit; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-26
    fn processHandshakeDatagramConcurrent(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, version: u32, ecn_bits: ?u8) void {
        if (bytes.len == 0 or (bytes[0] & 0x80) == 0) return;

        const norm_peer = normalizeAddr(&peer.storage, peer.len);
        const header = incoming.parseHandshakeHeader(bytes) catch return;

        current_io_endpoint = self;
        defer current_io_endpoint = null;

        const role_converted = @as(ep_types.EndpointRole, @enumFromInt(@intFromEnum(self.role)));
        var rx_ctx = incoming.RxContext{
            .allocator = &self.allocator,
            .conns = &self.conns,
            .accepted = &self.accepted,
            .cfg = &self.cfg,
            .send_fn = struct {
                fn send(peer_addr: conn_mod.SockAddr, data: []const u8) anyerror!usize {
                    const ep = current_io_endpoint.?;
                    return ep.sendTo(peer_addr, data);
                }
            }.send,
            .schedule_timer_fn = struct {
                fn schedule(conn_arg: *conn_mod.Connection, kind: ep_types.TimerKind, delay_ms: u32) anyerror!u64 {
                    const ep = current_io_endpoint.?;
                    return ep.scheduleConnPto(conn_arg, kind, delay_ms);
                }
            }.schedule,
            .send_initial_probe_fn = struct {
                fn probe(conn_arg: *conn_mod.Connection) anyerror!void {
                    const ep = current_io_endpoint.?;
                    return ep.clientSendInitialProbe(conn_arg);
                }
            }.probe,
            .setup_sender_fn = struct {
                fn setup(conn_arg: *conn_mod.Connection) void {
                    const ep = current_io_endpoint.?;
                    conn_arg.setSender(@ptrCast(ep), senderPaced);
                    conn_arg.setPtoDirtyNotifier(@ptrCast(ep), notifyPtoDirty);
                    conn_arg.setCloseNotifier(@ptrCast(ep), notifyConnectionClosed);
                }
            }.setup,
            .mark_pending_hs_send_fn = struct {
                fn mark(conn_arg: *conn_mod.Connection) void {
                    const ep = current_io_endpoint.?;
                    ep.markPendingHandshakeSend(conn_arg);
                }
            }.mark,
            .test_capture_enabled = self.test_capture_enabled,
            .endpoint_role = role_converted,
            .endpoint_ctx = self,
            .generated_token_secret = &self.generated_token_secret,
            .max_connections = self.cfg.max_connections,
            .anti_replay_cache = self.anti_replay_cache,
        };

        const conn = blk: {
            self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
            defer self.mu.unlock(std.Io.Threaded.global_single_threaded.io());

            const ph = hashSockaddr(&norm_peer.storage, norm_peer.len);
            const key = Key{ .peer_hash = ph, .dcid_hash = hashBytes(header.dcid) };
            var conn_opt: ?*conn_mod.Connection = null;
            if (self.conns.getPtr(key)) |entry| {
                conn_opt = entry.*;
            } else if (header.dcid.len == 0) {
                var iter = self.conns.iterator();
                while (iter.next()) |entry| {
                    if (entry.key_ptr.peer_hash == ph) {
                        conn_opt = entry.value_ptr.*;
                        break;
                    }
                }
            }

            const c = conn_opt orelse return;
            if (!c.acquireEndpointRxRef()) return;
            break :blk c;
        };
        defer conn.releaseEndpointRxRef();

        conn.endpoint_rx_serial_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer conn.endpoint_rx_serial_mu.unlock(std.Io.Threaded.global_single_threaded.io());

        incoming.processHandshakeResolved(&rx_ctx, norm_peer, bytes, version, ecn_bits, rx_ctx.send_fn, conn);
    }

    fn tryShortHeaderRouteCacheLen(
        self: *Endpoint,
        norm_peer: conn_mod.SockAddr,
        bytes: []const u8,
        peer_hash: u64,
        candidate_len: usize,
    ) ?CachedShortHeaderRoute {
        if (self.short_header_route_cache.len == 0) return null;
        if (candidate_len > std.math.maxInt(u8) or 1 + candidate_len > bytes.len) return null;

        const candidate_dcid = bytes[1 .. 1 + candidate_len];
        const dcid_hash = hashBytes(candidate_dcid);
        const idx = routeCacheIndex(peer_hash, dcid_hash, self.short_header_route_cache.len);
        const slot = &self.short_header_route_cache[idx];

        slot.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer slot.mu.unlock(std.Io.Threaded.global_single_threaded.io());

        if (slot.conn == null) return null;
        if (slot.peer_hash != peer_hash or slot.dcid_hash != dcid_hash or slot.dcid_len != candidate_len) return null;

        const c = slot.conn.?;
        if (c.closed) return null;
        if (!conn_mod.SockAddr.eq(&c.peer, &norm_peer)) return null;
        const matched_len = c.localDcidMatchLen(bytes, true) orelse return null;
        if (matched_len != candidate_len) return null;
        if (!c.acquireEndpointRxRef()) return null;

        return .{
            .conn = c,
            .lookup_result = .{
                .conn = c,
                .dcid_len = matched_len,
                .nat_rebinding = false,
            },
        };
    }

    fn tryShortHeaderRouteCache(self: *Endpoint, norm_peer: conn_mod.SockAddr, bytes: []const u8, peer_hash: u64) ?CachedShortHeaderRoute {
        return self.tryShortHeaderRouteCacheLen(norm_peer, bytes, peer_hash, lookup.DEFAULT_DCID_LEN);
    }

    fn rememberShortHeaderRoute(self: *Endpoint, norm_peer: conn_mod.SockAddr, bytes: []const u8, lookup_result: lookup.LookupResult) void {
        const c = lookup_result.conn orelse return;
        if (lookup_result.nat_rebinding) return;
        if (lookup_result.dcid_len != lookup.DEFAULT_DCID_LEN) return;
        if (!conn_mod.SockAddr.eq(&c.peer, &norm_peer)) return;
        if (lookup_result.dcid_len > std.math.maxInt(u8) or 1 + lookup_result.dcid_len > bytes.len) return;
        if (self.short_header_route_cache.len == 0) return;

        const peer_hash = hashSockaddr(&norm_peer.storage, norm_peer.len);
        const candidate_dcid = bytes[1 .. 1 + lookup_result.dcid_len];
        const dcid_hash = hashBytes(candidate_dcid);
        const idx = routeCacheIndex(peer_hash, dcid_hash, self.short_header_route_cache.len);
        const slot = &self.short_header_route_cache[idx];

        slot.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer slot.mu.unlock(std.Io.Threaded.global_single_threaded.io());

        slot.peer_hash = peer_hash;
        slot.dcid_hash = dcid_hash;
        slot.dcid_len = @intCast(lookup_result.dcid_len);
        slot.conn = c;
    }

    pub fn clearShortHeaderRouteCacheForConnection(self: *Endpoint, conn: *conn_mod.Connection) void {
        for (self.short_header_route_cache) |*slot| {
            slot.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
            if (slot.conn == conn) slot.conn = null;
            slot.mu.unlock(std.Io.Threaded.global_single_threaded.io());
        }
    }

    // CANARY: REQ=REQ-QUIC-HC-052; FEATURE="QUIC High-Concurrency Requests"; ASPECT=ShortHeaderRxLifetimeGuard; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-26
    // CANARY: REQ=REQ-QUIC-HC-054; FEATURE="QUIC High-Concurrency Requests"; ASPECT=EndpointShortHeaderLockSplit; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-26
    // CANARY: REQ=REQ-QUIC-HC-097; FEATURE="QUIC High-Concurrency Requests"; ASPECT=ShortHeaderPhaseTiming; STATUS=IMPL; TEST=test_quic_condition_timedwait_cadence; OWNER=transport; UPDATED=2026-05-27
    fn processShortHeaderDatagramConcurrent(
        self: *Endpoint,
        peer: conn_mod.SockAddr,
        bytes: []const u8,
        ecn_bits: ?u8,
    ) incoming.ShortHeaderTimingStats {
        var timing = incoming.ShortHeaderTimingStats{};
        if (bytes.len == 0 or (bytes[0] & 0x80) != 0) return timing;

        const detailed_timing = self.short_header_timing_enabled;
        const norm_peer = normalizeAddr(&peer.storage, peer.len);
        var lookup_result = lookup.LookupResult{
            .conn = null,
            .dcid_len = 0,
            .nat_rebinding = false,
        };

        const conn = blk: {
            const map_start_ns = if (detailed_timing) nowNsMonotonic() else 0;
            const peer_h = hashSockaddr(&norm_peer.storage, norm_peer.len);

            if (self.tryShortHeaderRouteCache(norm_peer, bytes, peer_h)) |cached| {
                lookup_result = cached.lookup_result;
                if (detailed_timing) timing.endpoint_map_ns += elapsedNsSince(map_start_ns);
                break :blk cached.conn;
            }

            self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());

            lookup_result = lookup.findConnectionByDcid(&self.conns, norm_peer, bytes, null);
            if (lookup_result.conn) |c| {
                if (lookup_result.nat_rebinding or !conn_mod.SockAddr.eq(&c.peer, &norm_peer)) {
                    if (!self.onPathAddressChanged(c, norm_peer, peer_h, lookup_result.dcid_len)) {
                        self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
                        if (shortHeaderDiagnosticsEnabled()) {
                            std.debug.print(
                                "short-header diag drop=endpoint_path_change peer_port={d} bytes={d} dcid_len={d}\n",
                                .{ peerPort(norm_peer), bytes.len, lookup_result.dcid_len },
                            );
                        }
                        if (detailed_timing) timing.endpoint_map_ns += elapsedNsSince(map_start_ns);
                        return timing;
                    }
                }
            } else {
                self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
                if (shortHeaderDiagnosticsEnabled()) {
                    std.debug.print(
                        "short-header diag drop=endpoint_lookup_miss peer_port={d} bytes={d} dcid_len={d}\n",
                        .{ peerPort(norm_peer), bytes.len, lookup_result.dcid_len },
                    );
                }
                if (detailed_timing) timing.endpoint_map_ns += elapsedNsSince(map_start_ns);
                return timing;
            }

            const c = lookup_result.conn.?;
            if (!c.acquireEndpointRxRef()) {
                self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
                if (shortHeaderDiagnosticsEnabled()) {
                    std.debug.print(
                        "short-header diag drop=endpoint_rx_ref peer_port={d} bytes={d} dcid_len={d}\n",
                        .{ peerPort(norm_peer), bytes.len, lookup_result.dcid_len },
                    );
                }
                if (detailed_timing) timing.endpoint_map_ns += elapsedNsSince(map_start_ns);
                return timing;
            }
            self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
            self.rememberShortHeaderRoute(norm_peer, bytes, lookup_result);
            if (detailed_timing) timing.endpoint_map_ns += elapsedNsSince(map_start_ns);
            break :blk c;
        };
        defer conn.releaseEndpointRxRef();

        current_io_endpoint = self;
        defer current_io_endpoint = null;

        const role_converted = @as(ep_types.EndpointRole, @enumFromInt(@intFromEnum(self.role)));
        var rx_ctx = incoming.RxContext{
            .allocator = &self.allocator,
            .conns = &self.conns,
            .accepted = &self.accepted,
            .cfg = &self.cfg,
            .send_fn = struct {
                fn send(peer_addr: conn_mod.SockAddr, data: []const u8) anyerror!usize {
                    const ep = current_io_endpoint.?;
                    return ep.sendTo(peer_addr, data);
                }
            }.send,
            .schedule_timer_fn = struct {
                fn schedule(conn_arg: *conn_mod.Connection, kind: ep_types.TimerKind, delay_ms: u32) anyerror!u64 {
                    const ep = current_io_endpoint.?;
                    return ep.scheduleConnPto(conn_arg, kind, delay_ms);
                }
            }.schedule,
            .send_initial_probe_fn = struct {
                fn probe(conn_arg: *conn_mod.Connection) anyerror!void {
                    const ep = current_io_endpoint.?;
                    return ep.clientSendInitialProbe(conn_arg);
                }
            }.probe,
            .setup_sender_fn = struct {
                fn setup(conn_arg: *conn_mod.Connection) void {
                    const ep = current_io_endpoint.?;
                    conn_arg.setSender(@ptrCast(ep), senderPaced);
                    conn_arg.setPtoDirtyNotifier(@ptrCast(ep), notifyPtoDirty);
                    conn_arg.setCloseNotifier(@ptrCast(ep), notifyConnectionClosed);
                }
            }.setup,
            .mark_pending_hs_send_fn = struct {
                fn mark(conn_arg: *conn_mod.Connection) void {
                    const ep = current_io_endpoint.?;
                    ep.markPendingHandshakeSend(conn_arg);
                }
            }.mark,
            .test_capture_enabled = self.test_capture_enabled,
            .endpoint_role = role_converted,
            .endpoint_ctx = self,
            .generated_token_secret = &self.generated_token_secret,
            .max_connections = self.cfg.max_connections,
            .short_header_timing = if (detailed_timing) &timing else null,
            .anti_replay_cache = self.anti_replay_cache,
        };

        incoming.processShortHeaderResolved(&rx_ctx, norm_peer, bytes, ecn_bits, rx_ctx.send_fn, lookup_result);
        self.maybeQueueDeferredAccepted(conn);
        return timing;
    }

    /// Create server-side represented connection (used by client dialing logic).
    /// Phase 8c: sock_fd set to -1 (I/O goes through endpoint transport)
    pub fn connectTo(self: *Endpoint, hostport: []const u8) !conn_mod.Connection {
        _ = self; // unused
        const peer = try utils.resolveAny(hostport, .udp);
        return .{ .id = 0, .role = .Client, .sock_fd = -1, .peer = peer, .tls_inbox = .empty };
    }

    /// Create client-side connection object referencing remote host:port.
    /// Thread-safe: acquires endpoint mutex to protect connection map mutation.
    pub fn connectClient(self: *Endpoint, hostport: []const u8) !*conn_mod.Connection {
        const peer = try utils.resolveAny(hostport, .udp);
        const ph = hashSockaddr(&peer.storage, peer.len);
        const version = if (self.cfg.version == .v2) packet.QUIC_V2 else packet.QUIC_V1;

        self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mu.unlock(std.Io.Threaded.global_single_threaded.io());

        // Delegate to client module for connection creation
        // Phase 8c: Pass invalid socket for sock_fd (I/O now via transport abstraction)
        const c = try client_mod.createClientConnection(
            &self.allocator,
            peer,
            utils.invalidSocket(),
            self.cfg,
            version,
            &self.conns,
            ph,
        );

        // Install paced sender callback (requires Endpoint context)
        c.setSender(@ptrCast(self), senderPaced);
        // Install PTO-dirty notifier so markPtoDirty() updates pto_dirty_set (#182).
        c.setPtoDirtyNotifier(@ptrCast(self), notifyPtoDirty);
        c.setCloseNotifier(@ptrCast(self), notifyConnectionClosed);

        return c;
    }

    pub fn markPendingHandshakeSend(self: *Endpoint, c: *conn_mod.Connection) void {
        c.pending_hs_send = true;
        self.pending_hs_send_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        const already_pending = self.pending_hs_send_set.contains(c);
        self.pending_hs_send_set.put(c, {}) catch |err| {
            self.pending_hs_send_mu.unlock(std.Io.Threaded.global_single_threaded.io());
            logger.debugPrint("[ENDPOINT] pending_hs_send_set.put failed: {s}\n", .{@errorName(err)});
            return;
        };
        self.pending_hs_send_mu.unlock(std.Io.Threaded.global_single_threaded.io());
        if (!already_pending) _ = self.pending_hs_send_count.fetchAdd(1, .release);
    }

    /// Look up a connection by peer address + short-header packet bytes.
    ///
    /// Thin public wrapper over `endpoint/lookup.findConnectionByDcid` that
    /// exposes the connection-table routing path (RFC 9000 §5.1 / §5.2) for
    /// benchmarks and observability tooling without requiring direct access
    /// to the endpoint's internal connection map.
    ///
    /// `packet_bytes` must be the raw short-header packet (the first byte is
    /// the header form; DCID starts at byte 1). Passing `null` for the NAT
    /// rebinding callback means rebinding is detected-but-not-actioned here;
    /// the real packet ingress path still drives path validation.
    ///
    /// Returns the matching Connection, or null if no entry routes. This is
    /// read-only and holds no mutex -- the caller is responsible for ensuring
    /// the connection table is stable (e.g., no concurrent connectClient /
    /// accept during the lookup window). Benchmarks satisfy this implicitly
    /// by running single-threaded against a pre-populated endpoint.
    pub fn findConnectionByDcid(
        self: *Endpoint,
        peer: conn_mod.SockAddr,
        packet_bytes: []const u8,
    ) ?*conn_mod.Connection {
        return lookup.findConnectionByDcid(&self.conns, peer, packet_bytes, null).conn;
    }

    /// Transmit minimal Initial packet (PING) to elicit Version Negotiation or SH.
    pub fn clientSendInitialProbe(self: *Endpoint, c: *conn_mod.Connection) !void {
        // Set up client transport parameters for TLS handshake
        // Transport parameter setup is critical -- without it the handshake
        // will produce an invalid ClientHello.  Propagate the error.
        try handshake_integration.setupClientTransportParams(c, &self.cfg, self.allocator);

        // Defensive: Initial-level onSecretAvailable callbacks are no-ops today
        // (RFC 9001 §5.2 -- Initial keys are derived by the QUIC layer, not TLS),
        // but future 0-RTT or HelloRetryRequest work could install secrets via
        // the TLS callback path. Wrap here -- the outermost frame that owns the
        // connection pointer for the duration of the TLS work driven by
        // sendInitialProbe -- so callbacks always see a valid connection.
        handshake_integration.setCurrentConnection(c);
        defer handshake_integration.clearCurrentConnection();

        // Delegate to client module for Initial packet construction and sending
        var ctx = client_mod.ClientContext{
            .allocator = &self.allocator,
            .conn = c,
            .sender_ctx = @ptrCast(self),
            .send_fn = &Endpoint.sendToWrapper,
            .peer = c.peer,
        };
        try client_mod.sendInitialProbe(&ctx);

        // Arm Initial PTO (requires Endpoint context)
        c.computeAndMaybeArmPtoInitial(self);
    }

    /// Schedule generic timer firing after delay_ms.
    /// Thread-safe: acquires timer_mu to protect timer queue and next_timer_id.
    pub fn scheduleTimer(self: *Endpoint, delay_ms: u32) !u64 {
        self.timer_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.timer_mu.unlock(std.Io.Threaded.global_single_threaded.io());
        return self.scheduleTimerLocked(delay_ms);
    }

    /// Schedule generic timer (caller must hold timer_mu).
    fn scheduleTimerLocked(self: *Endpoint, delay_ms: u32) !u64 {
        const id = self.next_timer_id;
        self.next_timer_id +%= 1;
        const now_ms: i64 = nowMsMonotonic();
        const deadline: i64 = now_ms + @as(i64, @intCast(delay_ms));
        try self.pushTimerLocked(.{ .deadline_ms = deadline, .id = id, .kind = .Generic, .conn = null });
        return id;
    }

    /// Schedule connection-owned PTO/PMTUD timer tied to a specific connection and space.
    /// Thread-safe: acquires timer_mu to protect timer queue and next_timer_id.
    pub fn scheduleConnPto(self: *Endpoint, c: *conn_mod.Connection, kind: TimerKind, delay_ms: u32) !u64 {
        self.timer_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.timer_mu.unlock(std.Io.Threaded.global_single_threaded.io());
        return self.scheduleConnPtoLocked(c, kind, delay_ms);
    }

    /// Schedule connection PTO timer (caller must hold timer_mu).
    fn scheduleConnPtoLocked(self: *Endpoint, c: *conn_mod.Connection, kind: TimerKind, delay_ms: u32) !u64 {
        const id = self.next_timer_id;
        self.next_timer_id +%= 1;
        const now_ms: i64 = nowMsMonotonic();
        const deadline: i64 = now_ms + @as(i64, @intCast(delay_ms));
        // PTO and probe timers follow RFC 9002 §6 (loss detection) and §7 (PMTUD pacing).
        try self.pushTimerLocked(.{ .deadline_ms = deadline, .id = id, .kind = kind, .conn = c });
        return id;
    }

    fn pushTimerLocked(self: *Endpoint, timer: Timer) !void {
        try timerPushIndexed(&self.timers, &self.timer_index, self.allocator, timer);
    }

    fn removeTimerAtLocked(self: *Endpoint, idx: usize) Timer {
        return timerRemoveAtIndexed(&self.timers, &self.timer_index, idx);
    }

    /// Schedule a paced send for a connection after delay_ns.
    /// Thread-safe: acquires timer_mu to protect timer queue.
    ///
    /// Preserves nanosecond precision of `delay_ns` via `Timer.deadline_ns_extra`
    /// — see #158 closure.
    fn schedulePaced(self: *Endpoint, c: *conn_mod.Connection, delay_ns: u64, owned_bytes: []u8) !u64 {
        self.timer_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.timer_mu.unlock(std.Io.Threaded.global_single_threaded.io());
        const id = self.next_timer_id;
        self.next_timer_id +%= 1;

        // Cap pacing delays at 100 ms to keep tests deterministic and fast.
        const max_pacing_ns: u64 = 100 * std.time.ns_per_ms;
        const clamped_delay_ns: u64 = @min(delay_ns, max_pacing_ns);

        const now_ns: i128 = nowNsMonotonic();
        const deadline_ns_total: i128 = now_ns + @as(i128, clamped_delay_ns);
        const deadline_ms_part: i64 = @intCast(@divTrunc(deadline_ns_total, std.time.ns_per_ms));
        const deadline_ns_residual: u32 = @intCast(@mod(deadline_ns_total, std.time.ns_per_ms));

        try self.pushTimerLocked(.{
            .deadline_ms = deadline_ms_part,
            .deadline_ns_extra = deadline_ns_residual,
            .id = id,
            .kind = .Generic,
            .conn = c,
            .paced = true,
            .payload = owned_bytes,
            .paced_peer = c.peer,
        });
        return id;
    }

    /// Cancel a pending timer id.
    /// Thread-safe: acquires timer_mu to protect timer queue.
    pub fn cancelTimer(self: *Endpoint, id: u64) bool {
        self.timer_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.timer_mu.unlock(std.Io.Threaded.global_single_threaded.io());
        return self.cancelTimerLocked(id);
    }

    /// Cancel a pending timer (caller must hold timer_mu).
    fn cancelTimerLocked(self: *Endpoint, id: u64) bool {
        const idx = self.timer_index.get(id) orelse return false;
        if (idx >= self.timers.items.len or self.timers.items[idx].id != id) {
            _ = self.timer_index.remove(id);
            return false;
        }
        _ = self.removeTimerAtLocked(idx);
        return true;
    }

    pub fn removeTimersForConnection(self: *Endpoint, conn: *conn_mod.Connection) void {
        self.timer_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.timer_mu.unlock(std.Io.Threaded.global_single_threaded.io());
        self.removeTimersForConnectionLocked(conn);
    }

    fn removeTimersForConnectionLocked(self: *Endpoint, conn: *conn_mod.Connection) void {
        var i: usize = 0;
        while (i < self.timers.items.len) {
            const timer = self.timers.items[i];
            if (timer.conn) |tc| {
                if (tc == conn) {
                    if (timer.paced) if (timer.payload) |p| self.allocator.free(p);
                    _ = self.removeTimerAtLocked(i);
                    continue;
                }
            }
            i += 1;
        }
    }

    /// Drive network I/O, timers, and paced send for up to timeout_ms milliseconds.
    /// Phase 8a: Uses transport abstraction if available, otherwise uses platform-specific backend.
    /// Poll for events with timeout via transport abstraction.
    /// Phase 8c: Always uses transport (no fallback to sock_fd/epoll).
    pub fn poll(self: *Endpoint, timeout_ms: i32) !void {
        _ = try self.pollWithStats(timeout_ms);
    }

    /// Variant of poll that returns the number of datagrams processed.
    /// Useful for callers that need to prioritize receives over sends.
    ///
    /// Thread-safety: Acquires endpoint mutex around shared state access
    /// (connection map, timers, accepted queue). The transport poll itself
    /// runs outside the lock to avoid blocking other threads during I/O wait.
    pub fn pollWithStats(self: *Endpoint, timeout_ms: i32) !PollStats {
        var stats = PollStats{};

        // Phase 1 (removed): Timer processing consolidated into Phase 5 to
        // eliminate one mu+timer_mu acquisition per poll cycle. Phase 2 already
        // accounts for timer deadlines in the effective timeout, so expired
        // timers are caught promptly after transport.poll() returns.

        // Phase 2: Calculate effective timeout (timer_mu only - reads timer deadlines)
        var eff_timeout: i32 = undefined;
        {
            self.timer_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
            defer self.timer_mu.unlock(std.Io.Threaded.global_single_threaded.io());
            const now_ms: i64 = nowMsMonotonic();
            eff_timeout = self.nextTimeoutFromTimers(now_ms, timeout_ms);
            if (eff_timeout < 0) eff_timeout = -1;
        }

        // Phase 3: Poll transport (NO lock - blocks until data available or timeout)
        const transport_poll_start_ns = nowNsMonotonic();
        try self.transport.poll(eff_timeout);
        stats.transport_poll_ns = elapsedNsSince(transport_poll_start_ns);

        // Phase 4: Drain packets - receive batch then process each datagram.
        // Lock is acquired per-batch and released between iterations so handler
        // threads (popAccepted, scheduleTimer) get fair access.
        {
            const recv_process_start_ns = nowNsMonotonic();
            defer stats.recv_process_ns = elapsedNsSince(recv_process_start_ns);
            const max_packets_this_poll = maxPacketsPerPollCycleForRole(self.role);
            const max_short_header_packets_this_poll = maxShortHeaderPacketsPerPollCycleForRole(self.role);
            const max_initial_packets_this_poll = maxInitialPacketsPerPollCycleForRole(self.role);
            var recv_bufs: [udp_transport_mod.UdpBatchCap][4096]u8 = undefined;
            var recv_slots: [udp_transport_mod.UdpBatchCap]transport_mod.RecvBatchSlot = undefined;
            for (&recv_slots, 0..) |*slot, i| {
                slot.* = .{
                    .buf = recv_bufs[i][0..],
                    .n = 0,
                    .peer = .{},
                    .ecn = null,
                };
            }
            var initial_packets_processed: usize = 0;
            var short_header_packets_processed: usize = 0;
            drain_loop: while (true) {
                if (stats.packets_processed >= max_packets_this_poll) break :drain_loop;
                if (serverShortHeaderCadenceExpired(
                    self.role,
                    elapsedNsSince(recv_process_start_ns),
                    short_header_packets_processed,
                )) break :drain_loop;
                const packet_budget_left = max_packets_this_poll - stats.packets_processed;
                const recv_limit = @min(recv_slots.len, packet_budget_left);

                // 4a: Receive batch (no lock needed for transport recv)
                const batch_n = self.transport.recvBatch(recv_slots[0..recv_limit]) catch |err| {
                    if (err == error.WouldBlock) break;
                    return err;
                };
                if (batch_n == 0) break;

                // 4b: Process each datagram with a narrow endpoint lock. Do not
                // hold the global mutex across the whole received batch; a slow
                // packet path should not serialize unrelated accepts/timers for
                // every datagram already drained from the socket.
                // NOTE: PAR-002/003 batch HP removal + AEAD decrypt was removed
                // because it corrupted packet buffers — the batch path unmasked
                // headers in-place, then the sequential fallthrough did HP removal
                // again (double XOR = re-masked = AEAD auth failure = EOF).
                // Batch crypto requires a pre-decrypted fast path in
                // processShortHeader before it can be re-enabled.
                var i: usize = 0;
                while (i < batch_n) : (i += 1) {
                    const slot = recv_slots[i];
                    const datagram = slot.buf[0..slot.n];
                    var processed_short_header = false;
                    if (datagram.len > 0 and (datagram[0] & 0x80) == 0) {
                        const short_header_start_ns = nowNsMonotonic();
                        const short_timing = self.processShortHeaderDatagramConcurrent(slot.peer, datagram, slot.ecn);
                        stats.recv_short_header_ns += elapsedNsSince(short_header_start_ns);
                        stats.recv_short_endpoint_map_ns += short_timing.endpoint_map_ns;
                        stats.recv_short_rx_serial_wait_ns += short_timing.rx_serial_wait_ns;
                        stats.recv_short_conn_lock_wait_ns += short_timing.conn_lock_wait_ns;
                        stats.recv_short_decrypt_ns += short_timing.decrypt_ns;
                        stats.recv_short_frame_process_ns += short_timing.frame_process_ns;
                        stats.recv_short_ack_send_ns += short_timing.ack_send_ns;
                        short_header_packets_processed += 1;
                        processed_short_header = true;
                    } else {
                        const long_kind = classifyLongHeaderPacket(datagram);
                        const long_version = parseLongHeaderVersion(datagram) orelse 0;
                        // CANARY: REQ=REQ-QUIC-HC-064; FEATURE="QUIC High-Concurrency Requests"; ASPECT=InitialBurstBackpressure; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-26
                        // A simultaneous connection wave places every client
                        // Initial in the UDP FIFO before any client Handshake
                        // response can arrive. If the poller stops reading
                        // after a small Initial budget, those follow-up
                        // Handshake packets remain stuck behind unprocessed
                        // new-connection work and early clients time out even
                        // though the server already sent their first flight.
                        // Keep draining the socket, but shed surplus Initials
                        // in this cycle; client PTO retransmits them later.
                        if (long_kind == .Initial and initial_packets_processed >= max_initial_packets_this_poll) {
                            stats.packets_processed += 1;
                            continue;
                        }
                        if (self.role == .Server and
                            long_kind == .Initial and
                            (long_version == packet.QUIC_V1 or long_version == packet.QUIC_V2) and
                            (longHeaderPacketLength(datagram, long_version) orelse 0) == datagram.len)
                        {
                            const initial_start_ns = nowNsMonotonic();
                            self.processInitialDatagramConcurrent(slot.peer, datagram, long_version);
                            stats.recv_initial_ns += elapsedNsSince(initial_start_ns);
                        } else if (long_kind == .Handshake and
                            (long_version == packet.QUIC_V1 or long_version == packet.QUIC_V2) and
                            (longHeaderPacketLength(datagram, long_version) orelse 0) == datagram.len)
                        {
                            const handshake_start_ns = nowNsMonotonic();
                            self.processHandshakeDatagramConcurrent(slot.peer, datagram, long_version, slot.ecn);
                            stats.recv_handshake_ns += elapsedNsSince(handshake_start_ns);
                        } else {
                            const fallback_start_ns = nowNsMonotonic();
                            self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
                            self.processIncomingDatagram(slot.peer, datagram, slot.ecn);
                            self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
                            stats.recv_fallback_ns += elapsedNsSince(fallback_start_ns);
                        }
                        if (long_kind == .Initial) initial_packets_processed += 1;
                    }
                    stats.packets_processed += 1;
                    if (processed_short_header and short_header_packets_processed >= max_short_header_packets_this_poll) break :drain_loop;
                    if (processed_short_header and serverShortHeaderCadenceExpired(
                        self.role,
                        elapsedNsSince(recv_process_start_ns),
                        short_header_packets_processed,
                    )) break :drain_loop;
                }
                // mu released between datagrams — handler threads get a chance to run.

                if (batch_n < recv_limit) break;
                if (stats.packets_processed >= max_packets_this_poll) break :drain_loop;
            }
        }

        // Phase 4.5: Drain `pending_hs_send` retries. processInitial sets this
        // flag when sendHandshakePackets returns error.NoHandshakeKeys — i.e.,
        // the TLS state machine had not yet derived `hs_tx_keys` when the
        // first ClientHello-bearing Initial was processed. The fix paired
        // with this drain (incoming.zig:processInitial NoHandshakeKeys
        // branch) defers instead of dropping; here we retry the flush every
        // poll tick until it lands. This closes the production msft-graph
        // --workers 16 reproducer where 12/16 connections stalled past the
        // QUIC idle timeout because the server never re-attempted the
        // Handshake send after the first-tick miss.
        //
        // The pending set snapshots server-role connections with the flag set,
        // then retries outside the lock so a slow per-connection TLS poll
        // doesn't serialize unrelated handlers. The retry uses the same
        // sendToWrapper-style closure (current_io_endpoint thread-local)
        // that processIncomingDatagram and clientSendInitialProbe already
        // rely on, so no new lock-order surface is introduced.
        {
            const pending_hs_start_ns = nowNsMonotonic();
            defer stats.pending_hs_send_ns = elapsedNsSince(pending_hs_start_ns);
            var pending_hs_send_snapshot: std.ArrayList(*conn_mod.Connection) = .empty;
            defer pending_hs_send_snapshot.deinit(self.allocator);
            var stale_hs_send_snapshot: std.ArrayList(*conn_mod.Connection) = .empty;
            defer stale_hs_send_snapshot.deinit(self.allocator);

            if (self.pending_hs_send_count.load(.acquire) > 0) {
                self.pending_hs_send_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
                const pending_budget = @min(self.pending_hs_send_set.count(), max_pending_hs_send_retries_per_poll_cycle);
                pending_hs_send_snapshot.ensureTotalCapacity(self.allocator, pending_budget) catch |err| {
                    self.pending_hs_send_mu.unlock(std.Io.Threaded.global_single_threaded.io());
                    return err;
                };
                stale_hs_send_snapshot.ensureTotalCapacity(self.allocator, pending_budget) catch |err| {
                    self.pending_hs_send_mu.unlock(std.Io.Threaded.global_single_threaded.io());
                    return err;
                };
                var it = self.pending_hs_send_set.iterator();
                while (it.next()) |entry| {
                    const c = entry.key_ptr.*;
                    if (c.role == .Server and !c.closed and c.pending_hs_send) {
                        if (pending_hs_send_snapshot.items.len >= max_pending_hs_send_retries_per_poll_cycle) break;
                        pending_hs_send_snapshot.appendAssumeCapacity(c);
                    } else if (stale_hs_send_snapshot.items.len < pending_budget) {
                        stale_hs_send_snapshot.appendAssumeCapacity(c);
                    }
                }
                for (pending_hs_send_snapshot.items) |c| {
                    _ = self.pending_hs_send_set.remove(c);
                }
                for (stale_hs_send_snapshot.items) |c| {
                    _ = self.pending_hs_send_set.remove(c);
                }
                self.pending_hs_send_count.store(self.pending_hs_send_set.count(), .release);
                self.pending_hs_send_mu.unlock(std.Io.Threaded.global_single_threaded.io());
            }

            if (pending_hs_send_snapshot.items.len > 0) {
                current_io_endpoint = self;
                defer current_io_endpoint = null;

                const RetrySend = struct {
                    fn send(peer_addr: conn_mod.SockAddr, data: []const u8) anyerror!usize {
                        const ep = current_io_endpoint.?;
                        return ep.sendTo(peer_addr, data);
                    }
                };

                for (pending_hs_send_snapshot.items) |c| {
                    // CANARY: REQ=REQ-QUIC-HC-137; FEATURE="High-Concurrency Handshake"; ASPECT=PendingHandshakeSendSerialization; STATUS=TESTED; TEST=pending_hs_send_retry_waits_for_rx_serial_mutex; OWNER=transport; UPDATED=2026-05-28
                    //
                    // The normal Initial/Handshake receive paths hold this
                    // per-connection serial mutex while driving TLS
                    // processCrypto/pollCrypto. The deferred retry path must
                    // join that same serialization; otherwise one poll worker
                    // can drain pollCrypto while another worker is appending
                    // to the same TLS outbound CRYPTO ArrayList.
                    c.endpoint_rx_serial_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
                    defer c.endpoint_rx_serial_mu.unlock(std.Io.Threaded.global_single_threaded.io());

                    // The TLS callback path (onSecretAvailable) reads the
                    // current connection from a thread-local; install it
                    // before calling sendHandshakePackets so a Handshake-
                    // level secret derivation triggered by pollCrypto lands
                    // on this connection's hs_tx_keys / hs_rx_keys.
                    handshake_integration.setCurrentConnection(c);
                    defer handshake_integration.clearCurrentConnection();

                    var hs_ctx = handshake_integration.HandshakeContext{
                        .conn = c,
                        .peer = c.peer,
                        .allocator = &self.allocator,
                        .send_fn = RetrySend.send,
                        .cfg = &self.cfg,
                    };
                    handshake_integration.sendHandshakePackets(&hs_ctx) catch |err| {
                        if (err == error.NoHandshakeKeys) {
                            // Still no keys — leave the flag set; next tick
                            // will try again. pollCrypto inside
                            // sendHandshakePackets above already drove the
                            // TLS state machine; we just have to wait for
                            // the next inbound CRYPTO frame to advance it.
                            self.markPendingHandshakeSend(c);
                            continue;
                        }
                        // Any other error is unexpected here; log it and
                        // clear the flag so we don't loop on a permanent
                        // failure (e.g., closed TLS context).
                        c.last_handshake_error = err;
                        c.pending_hs_send = false;
                        logger.err(
                            "pollWithStats: pending sendHandshakePackets failed: {s}",
                            .{@errorName(err)},
                        );
                        continue;
                    };
                    // Success: clear the flag.
                    c.pending_hs_send = false;
                }
            }
        }

        // Phase 5: Process expired timers under mu+timer_mu, then arm PTO
        // timers outside mu (PAR-006: reduces mu contention).
        // processExpiredTimers releases/reacquires timer_mu internally for callbacks.
        //
        // #182 closure: drain the dirty subset only, not every active connection.
        // `pto_dirty_set` is maintained by `markPtoDirty()` under the dedicated
        // `pto_dirty_mu` leaf mutex (no lock-order conflict with `mu` or
        // `conn.mu`). Iteration cost is O(dirty), not O(active).
        {
            const timer_start_ns = nowNsMonotonic();
            defer stats.timer_process_ns = elapsedNsSince(timer_start_ns);
            self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
            self.timer_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
            self.processExpiredTimers(nowMsMonotonic());
            // timer_mu is held on return from processExpiredTimers
            self.timer_mu.unlock(std.Io.Threaded.global_single_threaded.io());
            self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
        }

        // CANARY: REQ=REQ-QUIC-HC-035; FEATURE="QUIC High-Concurrency Requests"; ASPECT=PtoDirtyDestroySerialization; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-26
        // Drain and recompute PTO-dirty connections under pto_lifetime_mu.
        // Geode's deferred-destroy path takes the same mutex around
        // api.destroy(); this prevents a destroy racing a snapshotted pointer
        // without holding pto_dirty_mu during recovery/timer recompute.
        {
            const pto_dirty_start_ns = nowNsMonotonic();
            defer stats.pto_dirty_ns = elapsedNsSince(pto_dirty_start_ns);
            self.pto_lifetime_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
            defer self.pto_lifetime_mu.unlock(std.Io.Threaded.global_single_threaded.io());

            var pto_dirty_snapshot: std.ArrayList(*conn_mod.Connection) = .empty;
            defer pto_dirty_snapshot.deinit(self.allocator);
            var stale_pto_dirty_snapshot: std.ArrayList(*conn_mod.Connection) = .empty;
            defer stale_pto_dirty_snapshot.deinit(self.allocator);
            if (self.pto_dirty_count.load(.acquire) > 0) {
                self.pto_dirty_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
                const pto_dirty_budget = @min(self.pto_dirty_set.count(), max_pto_dirty_recomputes_per_poll_cycle);
                pto_dirty_snapshot.ensureTotalCapacity(self.allocator, pto_dirty_budget) catch |err| {
                    self.pto_dirty_mu.unlock(std.Io.Threaded.global_single_threaded.io());
                    return err;
                };
                stale_pto_dirty_snapshot.ensureTotalCapacity(self.allocator, pto_dirty_budget) catch |err| {
                    self.pto_dirty_mu.unlock(std.Io.Threaded.global_single_threaded.io());
                    return err;
                };
                var dit = self.pto_dirty_set.iterator();
                while (dit.next()) |entry| {
                    const c = entry.key_ptr.*;
                    if (pto_dirty_snapshot.items.len + stale_pto_dirty_snapshot.items.len >= pto_dirty_budget) break;
                    if (!c.closed) {
                        c.pto_dirty.store(false, .release);
                        pto_dirty_snapshot.appendAssumeCapacity(c);
                    } else {
                        stale_pto_dirty_snapshot.appendAssumeCapacity(c);
                    }
                }
                // Drain the entries we snapshotted; connections past the budget
                // remain in pto_dirty_set with pto_dirty=true, preserving their
                // queued recompute for the next poll cycle.
                for (pto_dirty_snapshot.items) |c| {
                    _ = self.pto_dirty_set.remove(c);
                }
                for (stale_pto_dirty_snapshot.items) |c| {
                    _ = self.pto_dirty_set.remove(c);
                }
                self.pto_dirty_count.store(self.pto_dirty_set.count(), .release);
                self.pto_dirty_mu.unlock(std.Io.Threaded.global_single_threaded.io());

                for (pto_dirty_snapshot.items) |c| {
                    // CANARY: REQ=REQ-QUIC-HC-136; FEATURE="QUIC High-Concurrency Requests"; ASPECT=PtoRecomputeConnectionMutex; STATUS=TESTED; TEST=pto_dirty_recompute_waits_for_connection_mutex; OWNER=transport; UPDATED=2026-05-28
                    //
                    // PTO recompute mutates per-connection active/id fields and
                    // reads Recovery in-flight state. Geode response workers can
                    // concurrently write STREAM frames for the same connection,
                    // so serialize dirty recompute with writeStream(), ACK
                    // handling, and PTO expiry on the connection mutex.
                    c.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
                    if (!c.closed) {
                        c.computeAndMaybeArmPtoInitial(self);
                        c.computeAndMaybeArmPtoHandshake(self);
                        c.computeAndMaybeArmPto(self);
                    }
                    c.mu.unlock(std.Io.Threaded.global_single_threaded.io());
                }
            }
        }

        return stats;
    }

    fn drainReadable(self: *Endpoint) void {
        // Delegate to io module - but we need self for callbacks
        // Simple solution: use thread-local for now
        // TODO: Better solution would be to make IoContext accept an opaque user_data pointer
        current_io_endpoint = self;

        const ProcessWrapper = struct {
            fn process(peer: conn_mod.SockAddr, data: []const u8, ecn_bits: ?u8) void {
                if (current_io_endpoint) |ep| {
                    ep.processIncomingDatagram(peer, data, ecn_bits);
                }
            }
        };

        const IcmpWrapper = struct {
            fn handle(peer: conn_mod.SockAddr, quoted: []const u8, mtu: u16) void {
                if (current_io_endpoint) |ep| {
                    ep.handleIcmpPtb(peer, quoted, mtu);
                }
            }
        };

        // Phase 8c: Legacy IO path - pass -1 for sock_fd (I/O now via transport)
        const ctx = io_mod.IoContext{
            .sock_fd = -1,
            .process_fn = ProcessWrapper.process,
            .icmp_ptb_fn = IcmpWrapper.handle,
            .epoll_fd = self.epoll_fd,
        };
        io_mod.drainReadable(&ctx);
        current_io_endpoint = null;
    }

    /// Linux-only: drain MSG_ERRQUEUE to handle ICMP PTB and apply DPLPMTUD clamps.
    fn drainErrorQueue(self: *Endpoint) void {
        // Delegate to io module using thread-local for self reference
        current_io_endpoint = self;

        const IcmpWrapper = struct {
            fn handle(peer: conn_mod.SockAddr, quoted: []const u8, mtu: u16) void {
                if (current_io_endpoint) |ep| {
                    ep.handleIcmpPtb(peer, quoted, mtu);
                }
            }
        };

        const ProcessWrapper = struct {
            fn process(_: conn_mod.SockAddr, _: []const u8, _: ?u8) void {
                // Not used for error queue
            }
        };

        // Phase 8c: Legacy IO path - pass -1 for sock_fd (I/O now via transport)
        const ctx = io_mod.IoContext{
            .sock_fd = -1,
            .process_fn = ProcessWrapper.process,
            .icmp_ptb_fn = IcmpWrapper.handle,
            .epoll_fd = self.epoll_fd,
        };
        io_mod.drainErrorQueue(&ctx);
        current_io_endpoint = null;
    }

    /// appears in a plausible short-header QUIC at some reasonable offset.
    fn handleIcmpPtb(self: *Endpoint, peer: conn_mod.SockAddr, quoted_udp_payload: []const u8, reported_mtu: u16) void {
        const ph = hashSockaddr(&peer.storage, peer.len);
        var it = self.conns.iterator();
        while (it.next()) |e| {
            const c = e.value_ptr.*;
            if (e.key_ptr.*.peer_hash != ph) continue;
            const dcid_len: usize = c.our_scid.len;
            if (dcid_len == 0 or quoted_udp_payload.len < 1 + dcid_len) continue;
            // Scan first 64 bytes for a plausible short header match
            const scan_max: usize = @min(quoted_udp_payload.len, 64);
            var off: usize = 0;
            while (off + 1 + dcid_len <= scan_max) : (off += 1) {
                const first = quoted_udp_payload[off];
                if ((first & 0x80) != 0) continue; // not short header
                if (std.mem.eql(u8, c.our_scid.bytes[0..dcid_len], quoted_udp_payload[off + 1 .. off + 1 + dcid_len])) {
                    c.onIcmpPacketTooBig(reported_mtu);
                    return;
                }
            }
        }
    }

    /// TEST-ONLY: inject a synthetic ICMP PTB quote for a given peer and UDP payload.
    pub fn testInjectIcmpPtb(self: *Endpoint, peer: conn_mod.SockAddr, quoted_udp_payload: []const u8, reported_mtu: u16) void {
        self.handleIcmpPtb(peer, quoted_udp_payload, reported_mtu);
    }

    /// Helper: Create IoContext and call platform-specific poll backend.
    fn callPollBackend(self: *Endpoint, backend: lb.LoopBackend, timeout_ms: i32) !void {
        current_io_endpoint = self;
        defer current_io_endpoint = null;

        const ProcessWrapper = struct {
            fn process(peer: conn_mod.SockAddr, data: []const u8, ecn_bits: ?u8) void {
                if (current_io_endpoint) |ep| {
                    ep.processIncomingDatagram(peer, data, ecn_bits);
                }
            }
        };

        const IcmpWrapper = struct {
            fn handle(peer: conn_mod.SockAddr, quoted: []const u8, mtu: u16) void {
                if (current_io_endpoint) |ep| {
                    ep.handleIcmpPtb(peer, quoted, mtu);
                }
            }
        };

        // Phase 8c: Legacy IO path - pass -1 for sock_fd (I/O now via transport)
        const ctx = io_mod.IoContext{
            .sock_fd = -1,
            .process_fn = ProcessWrapper.process,
            .icmp_ptb_fn = IcmpWrapper.handle,
            .epoll_fd = if (backend == .epoll) self.epoll_fd else null,
        };

        switch (backend) {
            .epoll => try io_mod.pollEpollBackend(&ctx, timeout_ms),
            .kqueue => try io_mod.pollKqueueBackend(&ctx, timeout_ms),
            .iocp => try io_mod.pollIocpBackend(&ctx, timeout_ms),
        }
    }

    // Helper: Wrapper for sendTo to match incoming.SendFn signature
    fn sendToWrapper(ctx: ?*anyopaque, peer: conn_mod.SockAddr, data: []const u8) anyerror!usize {
        const self: *Endpoint = @ptrCast(@alignCast(ctx.?));
        return self.sendTo(peer, data);
    }

    // Helper: Wrapper for scheduleTimer to match incoming.ScheduleTimerFn signature
    fn scheduleTimerWrapper(ctx: ?*anyopaque, conn: *conn_mod.Connection, kind: ep_types.TimerKind, delay_ms: u32) anyerror!u64 {
        const self: *Endpoint = @ptrCast(@alignCast(ctx.?));
        return self.scheduleTimer(conn, kind, delay_ms);
    }

    // Helper: Wrapper for clientSendInitialProbe to match incoming.SendInitialProbeFn signature
    fn clientSendInitialProbeWrapper(ctx: ?*anyopaque, conn: *conn_mod.Connection) anyerror!void {
        const self: *Endpoint = @ptrCast(@alignCast(ctx.?));
        return self.clientSendInitialProbe(conn);
    }

    // Helper: Process Retry packet (RFC 9000 §17.2.5, RFC 9001 §5.8)
    fn processRetryPacket(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, version: u32) void {
        // Parse Retry header
        var i: usize = 5;
        if (i >= bytes.len) return;
        const dcid_len = bytes[i];
        i += 1;
        if (i + dcid_len > bytes.len) return;
        const retry_dcid = bytes[i .. i + dcid_len];
        i += dcid_len;
        if (i >= bytes.len) return;
        const scid_len = bytes[i];
        i += 1;
        if (i + scid_len > bytes.len) return;
        const scid = bytes[i .. i + scid_len];
        i += scid_len;
        if (bytes.len < 16 or i >= bytes.len - 16) return; // Need room for integrity tag
        const token_bytes = bytes[i .. bytes.len - 16];

        const Candidate = struct {
            fn retryIntegrity(candidate: *conn_mod.Connection, retry_packet: []const u8) struct { current: bool, original: bool } {
                const cand_current = candidate.peer_initial_dcid.bytes[0..candidate.peer_initial_dcid.len];
                const cand_original = candidate.original_dcid.bytes[0..candidate.original_dcid.len];
                return .{
                    .current = cand_current.len > 0 and packet.verifyRetry(cand_current, retry_packet),
                    .original = cand_original.len > 0 and packet.verifyRetry(cand_original, retry_packet),
                };
            }
        };

        // Lookup matching client connection. Retry DCID must equal the client's
        // Initial SCID that triggered Retry. Client connections are keyed by
        // peer+our_scid when created, so normal Retry routing is one hash lookup
        // even during very large fan-out.
        const ph = hashSockaddr(&peer.storage, peer.len);
        var c_found: ?*conn_mod.Connection = null;
        var verify_current: bool = false;
        var verify_original: bool = false;

        if (retry_dcid.len > 0) {
            const key = Key{ .peer_hash = ph, .dcid_hash = hashBytes(retry_dcid) };
            if (self.conns.getPtr(key)) |entry| {
                const candidate = entry.*;
                const dcid_matches = candidate.our_scid.len == retry_dcid.len and
                    std.mem.eql(u8, candidate.our_scid.bytes[0..candidate.our_scid.len], retry_dcid);
                if (candidate.role == .Client and dcid_matches) {
                    const integrity = Candidate.retryIntegrity(candidate, bytes);
                    c_found = candidate;
                    verify_current = integrity.current;
                    verify_original = integrity.original;
                }
            }
        }

        // Fallback to same-peer candidates if an older or test-only path failed
        // to register the client's SCID key. This preserves compatibility while
        // avoiding a whole-map scan for normal Retry handling.
        if (c_found == null) {
            var itc = self.conns.iterator();
            while (itc.next()) |e| {
                if (e.key_ptr.*.peer_hash != ph) continue;
                const candidate = e.value_ptr.*;
                if (candidate.role != .Client) continue;
                if (candidate.our_scid.len != retry_dcid.len) continue;
                if (!std.mem.eql(u8, candidate.our_scid.bytes[0..candidate.our_scid.len], retry_dcid)) continue;

                const integrity = Candidate.retryIntegrity(candidate, bytes);
                c_found = candidate;
                verify_current = integrity.current;
                verify_original = integrity.original;
                break;
            }
        }

        const c = c_found orelse return;
        c.retry_packets_observed +%= 1;

        // Verify Retry integrity using ODCID from current or original client Initial epoch.
        // Security: always enforce integrity verification regardless of allow_insecure;
        // that flag only governs certificate validation, not Retry integrity or CID matching.
        if (!(verify_current or verify_original)) {
            c.retry_reject_integrity +%= 1;
            return;
        }
        if (c.handshake_done_seen) {
            c.retry_reject_post_handshake +%= 1;
            return;
        }
        // RFC 9000 §17.2.5: A client accepts at most one Retry for a connection.
        // Once processed, all subsequent Retry packets are discarded.
        if (c.retry_received) {
            c.retry_reject_duplicate +%= 1;
            return;
        }

        // Store token and update version/DCID for next Initial
        c.initial_token.clearRetainingCapacity();
        // Token storage is critical for Retry flow -- without it the next Initial
        // will be rejected by the server. Log and abandon Retry processing on OOM.
        _ = c.initial_token.appendSlice(self.allocator, token_bytes) catch |err| {
            logger.debugPrint("[ENDPOINT] Retry token storage failed: {s}\n", .{@errorName(err)});
            return;
        };
        c.retry_received = true;
        c.retry_apply_count +%= 1;
        c.version = version;
        c.version_v2 = (version == packet.QUIC_V2);
        c.initial_version = version;
        c.peer_initial_dcid.len = @intCast(@min(scid.len, c.peer_initial_dcid.bytes.len));
        if (c.peer_initial_dcid.len > 0) @memcpy(c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len], scid[0..c.peer_initial_dcid.len]);

        // RFC 9000 §17.2.5: Client restarts Initial-space handshake state after Retry.
        // Keep transmit PN monotonic for interop trace checkers that enforce non-reset PN.
        c.pn_initial = .{};
        c.initial_rx_keys = null;
        c.initial_tx_keys = null;
        c.hs_rx_keys = null;
        c.hs_tx_keys = null;
        c.app_rx_keys = null;
        c.app_tx_keys = null;
        c.app_rx_secret = null;
        c.app_tx_secret = null;
        c.crypto_tx_off_initial = 0;
        c.crypto_rx_off_initial = 0;
        c.crypto_retx_initial_off = 0;
        if (c.crypto_retx_initial) |retx| {
            self.allocator.free(retx);
            c.crypto_retx_initial = null;
        }
        c.keylog_handshake_logged = false;
        c.keylog_app_logged = false;
        c.keylog_client_traffic_epoch = 0;
        c.keylog_server_traffic_epoch = 0;
        c.tls_inbox.clearRetainingCapacity();
        c.peer_finished_verified = false;
        c.server_hello_sent = false;
        c.handshake_packet_sent = false;
        c.handshake_done_sent = false;
        c.handshake_done_seen = false;

        // Recreate client TLS context so a fresh ClientHello is generated for the post-Retry Initial.
        if (c.tls_context) |tls_ctx| {
            tls_ctx.deinit();
            const local_tp: []const u8 = c.local_transport_params_raw orelse &[_]u8{};
            const fresh_tls = handshake_integration.createTlsContext(
                self.allocator,
                .Client,
                self.cfg.alpn,
                local_tp,
                null,
                null,
                self.cfg.allow_insecure,
                false,
                self.cfg.inline_client_cert_der,
                self.cfg.inline_client_priv_key,
            ) catch return;
            tls_ctx.* = fresh_tls;
            if (c.server_name) |name| {
                tls_ctx.config.server_name = name;
            }
        } else {
            return;
        }

        // Resend Initial with token -- failure here means the client cannot
        // complete the handshake after Retry; log for diagnosis.
        self.clientSendInitialProbe(c) catch |err| {
            logger.debugPrint("[ENDPOINT] Initial probe resend after Retry failed: {s}\n", .{@errorName(err)});
        };
    }

    fn processIncomingDatagram(self: *Endpoint, peer: conn_mod.SockAddr, bytes: []const u8, ecn_bits: ?u8) void {
        const norm_peer = normalizeAddr(&peer.storage, peer.len);
        // Process all packets in the datagram (may be coalesced)
        // RFC 9000 §12.2: "Senders can coalesce multiple QUIC packets into one UDP datagram"
        var remaining = bytes;

        // Temporarily set global endpoint pointer for callbacks
        current_io_endpoint = self;
        defer current_io_endpoint = null;

        // Create RxContext for delegation to incoming.zig modules
        const role_converted = @as(ep_types.EndpointRole, @enumFromInt(@intFromEnum(self.role)));

        var rx_ctx = incoming.RxContext{
            .allocator = &self.allocator,
            .conns = &self.conns,
            .accepted = &self.accepted,
            .cfg = &self.cfg,
            .send_fn = struct {
                fn send(peer_addr: conn_mod.SockAddr, data: []const u8) anyerror!usize {
                    const ep = current_io_endpoint.?;
                    return ep.sendTo(peer_addr, data);
                }
            }.send,
            .schedule_timer_fn = struct {
                fn schedule(conn: *conn_mod.Connection, kind: ep_types.TimerKind, delay_ms: u32) anyerror!u64 {
                    const ep = current_io_endpoint.?;
                    return ep.scheduleConnPto(conn, kind, delay_ms);
                }
            }.schedule,
            .send_initial_probe_fn = struct {
                fn probe(conn: *conn_mod.Connection) anyerror!void {
                    const ep = current_io_endpoint.?;
                    return ep.clientSendInitialProbe(conn);
                }
            }.probe,
            .setup_sender_fn = struct {
                fn setup(conn: *conn_mod.Connection) void {
                    const ep = current_io_endpoint.?;
                    conn.setSender(@ptrCast(ep), senderPaced);
                    conn.setPtoDirtyNotifier(@ptrCast(ep), notifyPtoDirty);
                    conn.setCloseNotifier(@ptrCast(ep), notifyConnectionClosed);
                }
            }.setup,
            .mark_pending_hs_send_fn = struct {
                fn mark(conn: *conn_mod.Connection) void {
                    const ep = current_io_endpoint.?;
                    ep.markPendingHandshakeSend(conn);
                }
            }.mark,
            .test_capture_enabled = self.test_capture_enabled,
            .endpoint_role = role_converted,
            .endpoint_ctx = self,
            .generated_token_secret = &self.generated_token_secret,
            .max_connections = self.cfg.max_connections,
            .anti_replay_cache = self.anti_replay_cache,
        };

        // Process packets until we've consumed all bytes
        while (remaining.len > 0) {
            if (remaining.len < 1) break;

            const first = remaining[0];
            const is_long = (first & 0x80) != 0;

            // Short header: Process and consume entire remaining buffer
            if (!is_long) {
                // Handle NAT rebinding detection
                const lookup_result = lookup.findConnectionByDcid(&self.conns, norm_peer, remaining, null);
                if (lookup_result.conn) |c| {
                    if (lookup_result.nat_rebinding or !conn_mod.SockAddr.eq(&c.peer, &norm_peer)) {
                        const peer_h = hashSockaddr(&norm_peer.storage, norm_peer.len);
                        if (!self.onPathAddressChanged(c, norm_peer, peer_h, lookup_result.dcid_len)) break;
                    }
                }
                incoming.processShortHeaderResolved(&rx_ctx, norm_peer, remaining, ecn_bits, rx_ctx.send_fn, lookup_result);
                break; // Short header packet consumes rest of datagram
            }

            // Long header: Need to determine packet length to know how much to consume
            if (remaining.len < 5) break;
            const version: u32 = (@as(u32, remaining[1]) << 24) | (@as(u32, remaining[2]) << 16) | (@as(u32, remaining[3]) << 8) | @as(u32, remaining[4]);

            // Try to determine packet length to know how much to consume
            var packet_len: usize = remaining.len; // Default to entire remaining buffer

            // For long header packets, we need to parse the header to find the packet length
            // The packet length is encoded after the connection IDs
            if (remaining.len >= 7) {
                // Skip to DCID length at byte 5
                const dcid_len: usize = remaining[5];
                if (dcid_len > 20) break;
                if (remaining.len >= 6 + dcid_len + 1) {
                    // Skip DCID and get SCID length
                    const scid_len: usize = remaining[6 + dcid_len];
                    if (scid_len > 20) break;
                    if (remaining.len >= 7 + dcid_len + scid_len) {
                        // Now we're at the variable-length integer for packet length
                        var offset: usize = 7 + dcid_len + scid_len;

                        // Version Negotiation packets don't have length field
                        if (version == 0) {
                            packet_len = remaining.len; // Use entire buffer for VN
                        }
                        // Retry packets also don't have a length field
                        else if (packet.longHeaderPacketType(version, first) == .Retry) {
                            packet_len = remaining.len; // Use entire buffer for Retry
                        }
                        // Initial, Handshake, and 0-RTT packets have length field
                        else {
                            // For Initial packets, skip token length varint
                            if (packet.longHeaderPacketType(version, first) == .Initial and remaining.len > offset) {
                                // Read token length as varint
                                const token_len_result = varint.decode(remaining[offset..]) catch {
                                    break; // Can't parse, treat as single packet
                                };
                                offset += token_len_result.n;
                                offset += @as(usize, @intCast(token_len_result.value)); // Skip token bytes
                            }

                            // Now read the packet length varint
                            if (remaining.len > offset) {
                                const len_result = varint.decode(remaining[offset..]) catch {
                                    break; // Can't parse, treat as single packet
                                };
                                offset += len_result.n;
                                // packet_len is header_so_far + payload_length + 16 (auth tag)
                                packet_len = offset + @as(usize, @intCast(len_result.value));
                                packet_len = @min(packet_len, remaining.len); // Don't exceed buffer
                            }
                        }
                    }
                }
            }

            // Extract just this packet
            const packet_bytes = remaining[0..packet_len];

            // Debug: log packet extraction
            const packet_ty = (packet_bytes[0] >> 4) & 0x03;
            const packet_kind = packet.longHeaderPacketType(version, packet_bytes[0]);
            logger.debugPrint("processIncomingDatagram: Extracted type {} packet, len={} from datagram offset={}\n", .{
                packet_ty,
                packet_len,
                bytes.len - remaining.len,
            });

            // Process the packet based on type
            // Re-parse packet type from THIS packet's first byte (for coalesced packets)

            if (version == 0) {
                incoming.processVersionNegotiation(&rx_ctx, norm_peer, packet_bytes);
            } else if (packet_kind == .Initial) {
                // Server-side version negotiation for unsupported versions.
                // This is required by the interop simulator readiness probe
                // (wait-for-it-quic), which sends an Initial-like packet with
                // an unknown version and expects a Version Negotiation reply.
                if (self.role == .Server and version != packet.QUIC_V1 and version != packet.QUIC_V2) {
                    var dcid: []const u8 = &[_]u8{};
                    var scid: []const u8 = &[_]u8{};
                    if (packet_bytes.len >= 7) {
                        const dcid_len: usize = packet_bytes[5];
                        if (dcid_len > 20) break;
                        if (packet_bytes.len >= 6 + dcid_len + 1) {
                            dcid = packet_bytes[6 .. 6 + dcid_len];
                            const scid_len_off = 6 + dcid_len;
                            const scid_len: usize = packet_bytes[scid_len_off];
                            if (scid_len > 20) break;
                            const scid_off = scid_len_off + 1;
                            if (packet_bytes.len >= scid_off + scid_len) {
                                scid = packet_bytes[scid_off .. scid_off + scid_len];
                            }
                        }
                    }
                    const supported_versions = [_]u32{ packet.QUIC_V1, packet.QUIC_V2 };
                    var vn_buf: [256]u8 = undefined;
                    if (encodeVersionNegotiationPacket(scid, dcid, &supported_versions, vn_buf[0..])) |vn_packet| {
                        // Fire-and-forget: Version Negotiation is best-effort;
                        // client will retry or time out.
                        _ = self.sendTo(norm_peer, vn_packet) catch |err| {
                            logger.debugPrint("[ENDPOINT] VN send failed: {s}\n", .{@errorName(err)});
                        };
                    } else |_| {}
                } else {
                    incoming.processInitial(&rx_ctx, norm_peer, packet_bytes, version);
                }
            } else if (packet_kind == .Retry) {
                self.processRetryPacket(norm_peer, packet_bytes, version);
            } else if (packet_kind == .Handshake) {
                incoming.processHandshake(&rx_ctx, norm_peer, packet_bytes, version, ecn_bits, rx_ctx.send_fn);
            }

            // Advance to next packet
            remaining = remaining[packet_len..];
        }
    }

    /// resets validation state and counters, installs new map key, and triggers validation
    /// as described in RFC 9000 §9.4/§9.5 for path migration.
    fn onPathAddressChanged(self: *Endpoint, c: *conn_mod.Connection, new_peer: conn_mod.SockAddr, new_peer_hash: u64, dcid_len: usize) bool {
        if (c.disable_active_migration_advertised) {
            logger.debugPrint("path: rejected address change after advertising disable_active_migration (dcid_len={d})\n", .{dcid_len});
            return false;
        }
        c.setPeer(new_peer);
        c.address_validated = false;
        c.bytes_rx_unvalidated = 0;
        c.bytes_tx_unvalidated = 0;
        c.path_validation_pending = false;
        c.path_validation_attempts = 0;
        c.path_validation_deadline_ns = 0;
        c.path_validation_failed = false;
        // Insert/refresh mapping keyed by new peer and our DCID
        const new_key = Key{ .peer_hash = new_peer_hash, .dcid_hash = hashBytes(c.our_scid.bytes[0..dcid_len]) };
        // OOM prevents registering the migrated path -- the connection becomes
        // unreachable for future inbound packets on the new address.
        _ = self.conns.put(new_key, c) catch |err| {
            logger.debugPrint("[ENDPOINT] path migration map insert failed: {s}\n", .{@errorName(err)});
        };
        // Trigger PATH_CHALLENGE if 1-RTT keys are available (§9.3):
        c.sendPathChallenge();
        logger.debugPrint("path: change detected dcid_len={d} triggering validation (phase={d})\n", .{ dcid_len, @intFromBool(c.tx_key_phase) });
        return true;
    }

    /// Mark path validated and clear unvalidated counters consistently.
    fn onPathValidated(self: *Endpoint, c: *conn_mod.Connection) void {
        _ = self; // unused
        c.path_validation_pending = false;
        c.path_validation_attempts = 0;
        c.path_validation_deadline_ns = 0;
        c.path_validation_failed = false;
        c.address_validated = true;
        c.bytes_rx_unvalidated = 0;
        c.bytes_tx_unvalidated = 0;
        logger.debugPrint("path: validated (peer={d} bytes_rx_unval reset)\n", .{c.peer.len});
    }

    fn nextTimeoutFromTimers(self: *Endpoint, now_ms: i64, requested_timeout_ms: i32) i32 {
        var eff = requested_timeout_ms;
        if (self.timers.items.len > 0) {
            const t = self.timers.items[0];
            const diff: i64 = t.deadline_ms - now_ms;
            const t_ms: i32 = if (diff <= 0) 0 else @intCast(@min(diff, @as(i64, std.math.maxInt(i32))));
            if (eff < 0 or t_ms < eff) eff = t_ms;
        }
        return eff;
    }

    /// Returns true if `c` still appears in either the live `conns` map or the
    /// `retired` list. Used by processExpiredTimers to guard against UAF when a
    /// Timer-captured *Connection has been freed before its deadline fires.
    /// Caller must hold mu.
    fn isConnectionLive(self: *Endpoint, c: *conn_mod.Connection) bool {
        var it = self.conns.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* == c) return true;
        }
        for (self.retired.items) |rc| {
            if (rc == c) return true;
        }
        return false;
    }

    /// Process expired timers: collect under timer_mu, fire callbacks outside it.
    ///
    /// Caller must hold mu (for connection callbacks). Caller must hold timer_mu
    /// on entry; this function releases timer_mu before firing callbacks (which
    /// may call scheduleConnPto/cancelTimer that re-acquire timer_mu), then
    /// re-acquires timer_mu before returning.
    fn processExpiredTimers(self: *Endpoint, now_ms: i64) void {
        // Collect expired timers under timer_mu (already held by caller)
        var expired_buf: [64]Timer = undefined;
        var expired_count: usize = 0;

        // Sub-millisecond timers (paced sends) need ns precision; capture once.
        const now_ns: i128 = nowNsMonotonic();

        while (self.timers.items.len > 0 and expired_count < expired_buf.len) {
            const t = self.timers.items[0];
            if (!timerExpired(t.deadline_ms, t.deadline_ns_extra, now_ms, now_ns)) break;
            expired_buf[expired_count] = t;
            expired_count += 1;
            _ = self.removeTimerAtLocked(0);
        }

        // Release timer_mu before firing callbacks (they may schedule new timers)
        self.timer_mu.unlock(std.Io.Threaded.global_single_threaded.io());

        // Fire callbacks under mu only (already held by caller).
        //
        // UAF guard: a Timer captures a raw `*Connection`. If the connection
        // was freed between schedule and fire (e.g. client goes silent
        // mid-handshake and the server tears down the Connection in a prior
        // poll cycle), dereferencing `t.conn` would be a use-after-free.
        // Validate the pointer against the live connection set (`conns`) and
        // the retired-but-not-destroyed list (`retired`) before touching it.
        // Dead connections produce a no-op; live ones still PTO-expire.
        //
        // #165 + #183 closure: collect paced sends into a sendBatch buffer
        // so a single `sendmmsg` syscall flushes up to UdpBatchCap packets at
        // once (Linux).
        const transport_mod_ns = @import("endpoint/transport.zig");
        var paced_batch: [16]transport_mod_ns.SendBatchItem = undefined;
        var paced_payloads: [16][]u8 = undefined;
        var paced_count: usize = 0;
        const flushBatch = struct {
            fn call(ep: *Endpoint, batch: []const transport_mod_ns.SendBatchItem, payloads: [][]u8, count: *usize) void {
                if (count.* == 0) return;
                if (ep.test_capture_enabled) {
                    for (batch[0..count.*]) |it| {
                        _ = ep.sendTo(it.peer, it.data) catch |err| {
                            logger.debugPrint("[ENDPOINT] paced send (capture path) failed: {s}\n", .{@errorName(err)});
                        };
                    }
                } else {
                    _ = ep.transport.sendBatch(batch[0..count.*]) catch |err| {
                        logger.debugPrint("[ENDPOINT] paced sendBatch failed: {s}; falling back to per-packet\n", .{@errorName(err)});
                        for (batch[0..count.*]) |it| {
                            _ = ep.sendTo(it.peer, it.data) catch |e2| {
                                logger.debugPrint("[ENDPOINT] paced fallback send failed: {s}\n", .{@errorName(e2)});
                            };
                        }
                    };
                }
                for (payloads[0..count.*]) |bytes| ep.allocator.free(bytes);
                count.* = 0;
            }
        }.call;
        for (expired_buf[0..expired_count]) |t| {
            switch (t.kind) {
                .Generic => {
                    if (t.paced) {
                        if (t.conn) |c| {
                            if (!self.isConnectionLive(c)) {
                                if (t.payload) |bytes| self.allocator.free(bytes);
                                continue;
                            }
                            if (t.payload) |bytes| {
                                const paced_peer = if (t.paced_peer) |peer| peer else c.peer;
                                paced_batch[paced_count] = .{ .peer = paced_peer, .data = bytes };
                                paced_payloads[paced_count] = bytes;
                                paced_count += 1;
                                if (paced_count == paced_batch.len) {
                                    flushBatch(self, &paced_batch, &paced_payloads, &paced_count);
                                }
                            }
                        }
                    }
                },
                .AppAckDelay => if (t.conn) |c| {
                    if (!self.isConnectionLive(c)) continue;
                    // CANARY: REQ=REQ-QUIC-HC-149; FEATURE="QUIC High-Concurrency Requests"; ASPECT=ServerDelayedAppAck; STATUS=IMPL; TEST=server_stream_ack_policy_defers_first_stream_ack_and_acks_second; OWNER=transport; UPDATED=2026-05-29
                    // The receive path defers the first server-side STREAM-only
                    // standalone ACK so request/response workloads can piggyback
                    // it on the response packet. This timer is the RFC 9000
                    // max_ack_delay fallback for upload-only or quiet peers.
                    c.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
                    defer c.mu.unlock(std.Io.Threaded.global_single_threaded.io());
                    if (c.app_ack_delay_timer_id == t.id) c.app_ack_delay_timer_id = 0;
                    if (c.app_ack_eliciting_since_ack == 0 or c.app_tx_keys == null) continue;

                    current_io_endpoint = self;
                    defer current_io_endpoint = null;

                    var ack_ctx = incoming.AckContext{
                        .allocator = &self.allocator,
                        .conn = c,
                        .peer = c.peer,
                        .send_fn = struct {
                            fn send(peer_addr: conn_mod.SockAddr, data: []const u8) anyerror!usize {
                                const ep = current_io_endpoint.?;
                                return ep.sendTo(peer_addr, data);
                            }
                        }.send,
                        .cfg = &self.cfg,
                        .test_capture_enabled = self.test_capture_enabled,
                    };
                    incoming.generateAndSendAck(
                        &ack_ctx,
                        .{ .saw_ack_eliciting = true },
                        null,
                    ) catch |err| {
                        logger.debugPrint("[ENDPOINT] delayed Application ACK failed: {s}\n", .{@errorName(err)});
                    };
                },
                .PtoInitial => if (t.conn) |c| {
                    if (!self.isConnectionLive(c)) continue;
                    // CANARY: REQ=REQ-QUIC-HC-070; FEATURE="QUIC High-Concurrency Requests"; ASPECT=PtoRecoveryMutex; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-27
                    // PTO expiry touches recovery packet accounting,
                    // retransmission buffers, and packet-number state. Serialize
                    // it with application writes and ACK processing on the
                    // connection mutex to keep burst-loss recovery deterministic.
                    c.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
                    defer c.mu.unlock(std.Io.Threaded.global_single_threaded.io());
                    c.setPtoExpiredInitial();
                    // PTO probe failure is non-fatal; timer will fire again on next PTO expiry.
                    self.sendPtoProbe(c, .PtoInitial) catch |err| {
                        logger.debugPrint("[ENDPOINT] PTO Initial probe failed: {s}\n", .{@errorName(err)});
                    };
                },
                .PtoHandshake => if (t.conn) |c| {
                    if (!self.isConnectionLive(c)) continue;
                    c.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
                    defer c.mu.unlock(std.Io.Threaded.global_single_threaded.io());
                    c.setPtoExpiredHandshake();
                    // PTO probe failure is non-fatal; timer will fire again on next PTO expiry.
                    self.sendPtoProbe(c, .PtoHandshake) catch |err| {
                        logger.debugPrint("[ENDPOINT] PTO Handshake probe failed: {s}\n", .{@errorName(err)});
                    };
                },
                .PtoApp => if (t.conn) |c| {
                    if (!self.isConnectionLive(c)) continue;
                    c.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
                    defer c.mu.unlock(std.Io.Threaded.global_single_threaded.io());
                    c.setPtoExpiredApp();
                },
                .Pmtud => if (t.conn) |c| {
                    if (!self.isConnectionLive(c)) continue;
                    c.pmtudOnTimer(self);
                },
            }
        }

        // Flush any residual paced packets (#165 + #183).
        flushBatch(self, &paced_batch, &paced_payloads, &paced_count);

        // Prune closed connections (under mu, which caller holds)
        self.pruneClosed();

        // Re-acquire timer_mu (caller expects it held on return)
        self.timer_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
    }

    /// TEST-ONLY: force all timers to expire immediately and process them once.
    pub fn forceExpireAllTimers(self: *Endpoint) void {
        self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        self.timer_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer {
            self.timer_mu.unlock(std.Io.Threaded.global_single_threaded.io());
            self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
        }
        const now_ms = nowMsMonotonic();
        var i: usize = 0;
        while (i < self.timers.items.len) : (i += 1) {
            self.timers.items[i].deadline_ms = now_ms;
            self.timers.items[i].deadline_ns_extra = 0;
        }
        timerHeapifyAll(&self.timers, &self.timer_index);
        self.processExpiredTimers(now_ms);
    }

    pub fn sendPtoProbe(self: *Endpoint, conn: *conn_mod.Connection, kind: TimerKind) !void {
        // Use pto module helpers (Phase 4b.5 Session 9)
        const sendFnWrapper = struct {
            fn send(ctx: *anyopaque, peer: conn_mod.SockAddr, data: []const u8) !usize {
                const ep: *Endpoint = @ptrCast(@alignCast(ctx));
                return ep.sendTo(peer, data);
            }
        }.send;

        var ctx = pto_mod.PtoContext{
            .conn = conn,
            .allocator = &self.allocator,
            .send_ctx = self,
            .send_fn = sendFnWrapper,
            .peer = conn.peer,
        };
        // Cast TimerKind to the types module version (they're identical)
        const pto_kind = @as(pto_mod.types.TimerKind, @enumFromInt(@intFromEnum(kind)));
        try pto_mod.sendPtoProbe(&ctx, pto_kind);
    }

    /// Close old connections from the same peer when a new connection completes its handshake.
    /// This prevents routing packets to stale connections with mismatched keys.
    /// Delegates to lifecycle module (Phase 10).
    pub fn closeStaleConnectionsForPeer(self: *Endpoint, new_conn: *conn_mod.Connection) void {
        var ctx = lifecycle_mod.LifecycleContext{
            .allocator = &self.allocator,
            .conns = &self.conns,
            .timers = &self.timers,
            .retired = &self.retired,
        };
        lifecycle_mod.closeStaleConnectionsForPeer(&ctx, new_conn);
    }

    /// Remove all map entries / timers referencing connections that have transitioned to closed state.
    /// Caller must hold mu. Acquires timer_mu internally for timer cleanup.
    fn pruneClosed(self: *Endpoint) void {
        if (self.closed_conn_count.load(.acquire) == 0) return;

        var closed_snapshot: std.ArrayList(*conn_mod.Connection) = .empty;
        defer closed_snapshot.deinit(self.allocator);

        self.closed_conn_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        closed_snapshot.ensureTotalCapacity(self.allocator, self.closed_conn_set.count()) catch |err| {
            self.closed_conn_mu.unlock(std.Io.Threaded.global_single_threaded.io());
            logger.debugPrint("[ENDPOINT] closed snapshot allocation failed: {s}\n", .{@errorName(err)});
            return;
        };
        var cit = self.closed_conn_set.iterator();
        while (cit.next()) |entry| {
            closed_snapshot.appendAssumeCapacity(entry.key_ptr.*);
        }
        self.closed_conn_set.clearRetainingCapacity();
        self.closed_conn_count.store(0, .release);
        self.closed_conn_mu.unlock(std.Io.Threaded.global_single_threaded.io());

        if (closed_snapshot.items.len == 0) return;

        var closed_set = std.AutoHashMap(*conn_mod.Connection, void).init(self.allocator);
        defer closed_set.deinit();
        closed_set.ensureTotalCapacity(@intCast(closed_snapshot.items.len)) catch |err| {
            logger.debugPrint("[ENDPOINT] closed set allocation failed: {s}\n", .{@errorName(err)});
            return;
        };
        for (closed_snapshot.items) |conn| {
            if (conn.closed) closed_set.putAssumeCapacity(conn, {});
        }
        if (closed_set.count() == 0) return;

        var keys_to_remove: std.ArrayList(Key) = .empty;
        defer keys_to_remove.deinit(self.allocator);
        var map_it = self.conns.iterator();
        while (map_it.next()) |entry| {
            if (closed_set.contains(entry.value_ptr.*)) {
                keys_to_remove.append(self.allocator, entry.key_ptr.*) catch |err| {
                    logger.err("closed prune keys.append failed (OOM): {s}", .{@errorName(err)});
                };
            }
        }
        for (keys_to_remove.items) |key| {
            _ = self.conns.remove(key);
        }

        self.timer_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.timer_mu.unlock(std.Io.Threaded.global_single_threaded.io());

        var ti: usize = 0;
        while (ti < self.timers.items.len) {
            const timer = self.timers.items[ti];
            if (timer.conn) |timer_conn| {
                if (closed_set.contains(timer_conn)) {
                    if (timer.paced) if (timer.payload) |payload| self.allocator.free(payload);
                    _ = self.removeTimerAtLocked(ti);
                    continue;
                }
            }
            ti += 1;
        }
        timerHeapifyAll(&self.timers, &self.timer_index);

        var retired_seen = std.AutoHashMap(*conn_mod.Connection, void).init(self.allocator);
        defer retired_seen.deinit();
        const use_retired_seen = blk: {
            retired_seen.ensureTotalCapacity(@intCast(self.retired.items.len + closed_set.count())) catch |err| {
                logger.debugPrint("[ENDPOINT] retired seen allocation failed: {s}\n", .{@errorName(err)});
                break :blk false;
            };
            for (self.retired.items) |retired_conn| retired_seen.putAssumeCapacity(retired_conn, {});
            break :blk true;
        };

        var closed_it = closed_set.iterator();
        while (closed_it.next()) |entry| {
            const conn = entry.key_ptr.*;
            if (use_retired_seen) {
                if (retired_seen.contains(conn)) continue;
                self.retired.append(self.allocator, conn) catch |err| {
                    logger.err("retired.append failed (OOM): {s}", .{@errorName(err)});
                    continue;
                };
                retired_seen.putAssumeCapacity(conn, {});
            } else {
                var already_retired = false;
                for (self.retired.items) |retired_conn| {
                    if (retired_conn == conn) {
                        already_retired = true;
                        break;
                    }
                }
                if (!already_retired) {
                    self.retired.append(self.allocator, conn) catch |err| {
                        logger.err("retired.append failed (OOM): {s}", .{@errorName(err)});
                    };
                }
            }
        }
    }
};

// PTO-dirty notification callback (#182 closure). Invoked by Connection's
// `markPtoDirty()` on the false→true transition. Updates the dirty hash set
// under the endpoint's dedicated `pto_dirty_mu` leaf lock (separate from `mu`
// so we avoid the lock-order inversion with `conn.mu`), then increments an
// atomic counter so the poll loop can short-circuit the dirty scan when nothing
// is pending. The order is important: publishing the count before the set entry
// lets poll drain an empty set and reset the count before the insert lands.
fn notifyPtoDirty(ctx: *anyopaque, conn: *conn_mod.Connection) void {
    const self: *Endpoint = @ptrCast(@alignCast(ctx));
    // Best-effort hash set update under the leaf mutex. If contention is
    // unbearable in a future profile, this can be replaced with a lock-free
    // intrusive linked list (CAS on a per-connection next pointer).
    self.pto_dirty_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
    const already_dirty = self.pto_dirty_set.contains(conn);
    self.pto_dirty_set.put(conn, {}) catch |err| {
        self.pto_dirty_mu.unlock(std.Io.Threaded.global_single_threaded.io());
        logger.debugPrint("[ENDPOINT] pto_dirty_set.put failed: {s}\n", .{@errorName(err)});
        return;
    };
    self.pto_dirty_mu.unlock(std.Io.Threaded.global_single_threaded.io());
    if (!already_dirty) _ = self.pto_dirty_count.fetchAdd(1, .release);
}

fn notifyConnectionClosed(ctx: *anyopaque, conn: *conn_mod.Connection) void {
    const self: *Endpoint = @ptrCast(@alignCast(ctx));
    self.closed_conn_mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
    const already_closed = self.closed_conn_set.contains(conn);
    self.closed_conn_set.put(conn, {}) catch |err| {
        self.closed_conn_mu.unlock(std.Io.Threaded.global_single_threaded.io());
        logger.debugPrint("[ENDPOINT] closed_conn_set.put failed: {s}\n", .{@errorName(err)});
        return;
    };
    self.closed_conn_mu.unlock(std.Io.Threaded.global_single_threaded.io());
    if (!already_closed) _ = self.closed_conn_count.fetchAdd(1, .release);
}

// Sender callback used by Connection for timer-driven pacing
fn senderPaced(ctx: *anyopaque, c: *conn_mod.Connection, data: []const u8) !usize {
    const self: *Endpoint = @ptrCast(@alignCast(ctx));
    // If pacing disabled, send directly
    if (!c.enable_pacing) {
        if (data.len == 141) {
            const sa: *const posix.sockaddr = @ptrCast(&c.peer.storage);
            if (sa.family == posix.AF.INET) {
                const sin: *const posix.sockaddr.in = @ptrCast(&c.peer.storage);
                const addr_bytes = @as([4]u8, @bitCast(sin.addr));
                logger.debugPrint("senderPaced using peer addr {}.{}.{}.{}:{}\n", .{ addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3], portFromNetwork(sin.port) });
            }
        }
        return self.sendTo(c.peer, data);
    }
    // Read recovery state lock-free via atomic mirrors (#160 closure).
    const delay_ns = recovery.computePacingDelayNs(
        c.rec.cwndSnapshot(),
        c.rec.bytesInFlightSnapshot(),
        c.rec.smoothedRttSnapshot(),
        c.rec.mdsSnapshot(),
    );
    // For very small pacing delays the cost of allocating + scheduling a timer
    // exceeds the actual delay being enforced; send immediately. (#158 closure)
    const inline_send_threshold_ns: u64 = 10_000;
    if (delay_ns < inline_send_threshold_ns) {
        return self.sendTo(c.peer, data);
    }
    // Own the payload and schedule a paced timer at full ns precision via
    // schedulePaced, which stores sub-ms residual in deadline_ns_extra.
    const owned = try self.allocator.alloc(u8, data.len);
    @memcpy(owned, data);
    _ = try self.schedulePaced(c, delay_ns, owned);
    // Report bytes as accepted; actual socket send happens when the timer fires.
    return data.len;
}

// Legacy poll_* functions removed - dead code (never called)
// Modern poll_*_backend() functions are used instead
// Helper functions parseIpv4() and resolveAny() moved to utils.zig

test "endpoint timers keep index consistent across heap operations" {
    const allocator = std.testing.allocator;

    var timers: std.ArrayList(Timer) = .empty;
    defer timers.deinit(allocator);
    var timer_index = std.AutoHashMap(u64, usize).init(allocator);
    defer timer_index.deinit();

    const Check = struct {
        fn call(list: *const std.ArrayList(Timer), index: *const std.AutoHashMap(u64, usize)) !void {
            try std.testing.expectEqual(list.items.len, index.count());

            for (list.items, 0..) |timer, idx| {
                try std.testing.expectEqual(idx, index.get(timer.id) orelse return error.MissingTimerIndex);
                const left = 2 * idx + 1;
                const right = left + 1;
                if (left < list.items.len) try std.testing.expect(!timerBefore(list.items[left], timer));
                if (right < list.items.len) try std.testing.expect(!timerBefore(list.items[right], timer));
            }
        }
    }.call;

    try timerPushIndexed(&timers, &timer_index, allocator, .{ .deadline_ms = 30, .id = 30 });
    try timerPushIndexed(&timers, &timer_index, allocator, .{ .deadline_ms = 10, .id = 10 });
    try timerPushIndexed(&timers, &timer_index, allocator, .{ .deadline_ms = 20, .id = 20 });
    try timerPushIndexed(&timers, &timer_index, allocator, .{ .deadline_ms = 40, .id = 40 });
    try Check(&timers, &timer_index);
    try std.testing.expectEqual(@as(u64, 10), timers.items[0].id);

    const remove_idx = timer_index.get(20) orelse return error.MissingTimerIndex;
    const removed = timerRemoveAtIndexed(&timers, &timer_index, remove_idx);
    try std.testing.expectEqual(@as(u64, 20), removed.id);
    try std.testing.expect(timer_index.get(20) == null);
    try Check(&timers, &timer_index);

    for (timers.items) |*timer| {
        timer.deadline_ms = 100 - @as(i64, @intCast(timer.id));
    }
    timerHeapifyAll(&timers, &timer_index);
    try Check(&timers, &timer_index);
}

test "endpoint client poll cycle fairness budget stays at one UDP batch" {
    try std.testing.expectEqual(udp_transport_mod.UdpBatchCap, maxPacketsPerPollCycleForRole(.Client));
}

test "endpoint server poll budget drains multiple UDP batches" {
    try std.testing.expectEqual(udp_transport_mod.UdpBatchCap * server_poll_receive_batches, maxPacketsPerPollCycleForRole(.Server));
    try std.testing.expect(maxPacketsPerPollCycleForRole(.Server) > maxPacketsPerPollCycleForRole(.Client));
}

test "endpoint short header poll budget keeps server app packets bounded" {
    try std.testing.expectEqual(maxPacketsPerPollCycleForRole(.Client), maxShortHeaderPacketsPerPollCycleForRole(.Client));
    try std.testing.expectEqual(udp_transport_mod.UdpBatchCap * server_short_header_receive_batches, maxShortHeaderPacketsPerPollCycleForRole(.Server));
    try std.testing.expectEqual(maxPacketsPerPollCycleForRole(.Server), maxShortHeaderPacketsPerPollCycleForRole(.Server));
    try std.testing.expect(maxShortHeaderPacketsPerPollCycleForRole(.Server) > 0);
}

test "endpoint server short header cadence yields after full slow batch" {
    try std.testing.expectEqual(udp_transport_mod.UdpBatchCap, server_short_header_cadence_min_packets);
    try std.testing.expect(!serverShortHeaderCadenceExpired(.Client, std.time.ns_per_s, server_short_header_cadence_min_packets));
    try std.testing.expect(!serverShortHeaderCadenceExpired(.Server, server_short_header_cadence_budget_ns, server_short_header_cadence_min_packets - 1));
    try std.testing.expect(!serverShortHeaderCadenceExpired(.Server, server_short_header_cadence_budget_ns - 1, server_short_header_cadence_min_packets));
    try std.testing.expect(serverShortHeaderCadenceExpired(.Server, server_short_header_cadence_budget_ns, server_short_header_cadence_min_packets));
}

test "endpoint pto dirty recompute has a poll cycle fairness budget" {
    try std.testing.expectEqual(udp_transport_mod.UdpBatchCap, max_pto_dirty_recomputes_per_poll_cycle);
    try std.testing.expect(max_pto_dirty_recomputes_per_poll_cycle >= udp_transport_mod.UdpBatchCap);
}

// =============================================================================
// Tests: Anti-replay cache wiring (RFC 8446 S8, RFC 9001 S9.2)
// =============================================================================

test "anti-replay: server endpoint creates cache when zero_rtt_anti_replay is true" {
    const alloc = std.testing.allocator;
    const config = cfg.QuicConfig{
        .alpn = &[_][]const u8{},
        .inline_server_cert_der = &[_]u8{0}, // Makes role = Server
        .zero_rtt_anti_replay = true,
    };
    var ep = try Endpoint.init(alloc, "127.0.0.1:0", &config);
    defer ep.deinit();

    // Server with zero_rtt_anti_replay=true must have a cache.
    try std.testing.expect(ep.anti_replay_cache != null);
}

test "anti-replay: server endpoint skips cache when zero_rtt_anti_replay is false" {
    const alloc = std.testing.allocator;
    const config = cfg.QuicConfig{
        .alpn = &[_][]const u8{},
        .inline_server_cert_der = &[_]u8{0}, // Makes role = Server
        .zero_rtt_anti_replay = false,
    };
    var ep = try Endpoint.init(alloc, "127.0.0.1:0", &config);
    defer ep.deinit();

    // Server with zero_rtt_anti_replay=false must NOT have a cache.
    try std.testing.expect(ep.anti_replay_cache == null);
}

test "anti-replay: client endpoint never creates cache" {
    const alloc = std.testing.allocator;
    const config = cfg.QuicConfig{
        .alpn = &[_][]const u8{},
        // No cert -> client role
        .zero_rtt_anti_replay = true,
    };
    var ep = try Endpoint.init(alloc, "127.0.0.1:0", &config);
    defer ep.deinit();

    // Clients never need an anti-replay cache (server-side only).
    try std.testing.expect(ep.anti_replay_cache == null);
}

test "anti-replay: accept0RTT rejects replay when cache is wired" {
    const alloc = std.testing.allocator;

    // Create a shared anti-replay cache (as the endpoint would).
    var cache = conn_mod.AntiReplayCache.init(alloc, 100, 10_000_000_000);
    defer cache.deinit();

    // Manually construct a minimal Connection on the stack. We only need the
    // fields that accept0RTT reads: anti_replay_cache, peer_initial_dcid,
    // and zero_rtt_accepted. Connection is a large struct so we zero-init
    // via undefined + selective field setting.
    var conn: conn_mod.Connection = undefined;
    conn.anti_replay_cache = &cache;
    conn.zero_rtt_accepted = false;

    // Set a deterministic peer_initial_dcid (simulates client's random DCID).
    conn.peer_initial_dcid.len = 8;
    @memcpy(conn.peer_initial_dcid.bytes[0..8], &[8]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x12, 0x34 });

    // First call: fresh ticket -- should accept.
    conn.accept0RTT();
    try std.testing.expect(conn.zero_rtt_accepted == true);

    // Reset for second attempt (simulating a replayed 0-RTT with same DCID).
    conn.zero_rtt_accepted = false;

    // Second call with same DCID: replay -- must reject.
    conn.accept0RTT();
    try std.testing.expect(conn.zero_rtt_accepted == false);
}

test "anti-replay: accept0RTT accepts unconditionally when cache is null" {
    var conn: conn_mod.Connection = undefined;
    conn.anti_replay_cache = null;
    conn.zero_rtt_accepted = false;
    conn.peer_initial_dcid.len = 4;
    @memcpy(conn.peer_initial_dcid.bytes[0..4], &[4]u8{ 0xAA, 0xBB, 0xCC, 0xDD });

    // Without cache, accept0RTT always accepts (backwards-compat path).
    conn.accept0RTT();
    try std.testing.expect(conn.zero_rtt_accepted == true);

    // Even a second call with the same DCID accepts (no replay detection).
    conn.zero_rtt_accepted = false;
    conn.accept0RTT();
    try std.testing.expect(conn.zero_rtt_accepted == true);
}
