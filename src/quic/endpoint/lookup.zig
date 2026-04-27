// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Connection lookup and routing.
//!
//! RFC 9000 §5.1: Connection ID Routing
//! RFC 9000 §5.2: Matching Packets to Connections
//! RFC 9000 §9.3: Response to Address Change (NAT rebinding)

const std = @import("std");
const logger = @import("quic_logger");
const types = @import("types");
const conn_mod = @import("quic_conn");
const posix = std.posix;

// =============================================================================
// Phase 4b.5: Inline Hash Helpers
// =============================================================================

/// Hash arbitrary bytes using Wyhash.
inline fn hashBytes(b: []const u8) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(b);
    return h.final();
}

/// Hash socket address structure.
inline fn hashSockaddr(sa: *const posix.sockaddr.storage, len: u32) u64 {
    const bytes = std.mem.asBytes(sa)[0..@intCast(len)];
    return hashBytes(bytes);
}

// =============================================================================
// Legacy Connection Table (Phase 4a)
// =============================================================================

/// Connection lookup table using composite key (peer + DCID).
/// RFC 9000 §5.1: Servers route packets using address tuple and DCID.
pub const ConnectionTable = struct {
    map: std.AutoHashMap(types.Key, *conn_mod.Connection),

    pub fn init(allocator: std.mem.Allocator) ConnectionTable {
        return .{
            .map = std.AutoHashMap(types.Key, *conn_mod.Connection).init(allocator),
        };
    }

    pub fn deinit(self: *ConnectionTable) void {
        self.map.deinit();
    }

    /// Insert a connection with the given key.
    pub fn insert(self: *ConnectionTable, key: types.Key, conn: *conn_mod.Connection) !void {
        try self.map.put(key, conn);
    }

    /// Lookup a connection by key.
    pub fn lookup(self: *ConnectionTable, key: types.Key) ?*conn_mod.Connection {
        return self.map.get(key);
    }

    /// Remove a connection by key.
    pub fn remove(self: *ConnectionTable, key: types.Key) bool {
        return self.map.remove(key);
    }

    /// Get the number of connections.
    pub fn count(self: *const ConnectionTable) usize {
        return self.map.count();
    }
};

/// Create a lookup key from peer hash and DCID hash.
pub fn makeKey(peer_hash: u64, dcid_hash: u64) types.Key {
    return .{ .peer_hash = peer_hash, .dcid_hash = dcid_hash };
}

// =============================================================================
// Phase 4b.5: Extracted Connection Lookup (Session 3)
// =============================================================================

/// Result of connection lookup for short header packets.
pub const LookupResult = struct {
    /// Found connection, or null if no match
    conn: ?*conn_mod.Connection,
    /// DCID length used for matching (0 if no connection found)
    dcid_len: usize,
    /// True if NAT rebinding was detected (peer hash changed)
    nat_rebinding: bool,
};

/// Callback invoked when NAT rebinding is detected.
/// This allows updating connection table keys and triggering path validation.
pub const OnPathChangedFn = *const fn (
    conn: *conn_mod.Connection,
    new_peer: conn_mod.SockAddr,
    new_peer_hash: u64,
    dcid_len: usize,
) anyerror!void;

/// Default DCID length issued by the server (RFC 9000 §5.1 chooses an 8-byte
/// CID as the canonical compromise between collision resistance and packet
/// overhead). The lookup fast path tries this length first because the
/// overwhelming majority of short-header packets carry a CID issued by us.
pub const DEFAULT_DCID_LEN: usize = 8;

/// Find connection by DCID in short header packet.
/// Extracted from endpoint.zig lines 1104-1195 (Phase 4b.5 Session 3).
///
/// Lookup strategy (RFC 9000 §5.2, §9.3):
///
/// **Fast path (#154 closure)**: Try the default 8-byte DCID length first.
///   For server endpoints all CIDs we issue are 8 bytes (see
///   `acquireLocalCid` in `methods_c.zig`), so this path resolves in a single
///   AutoHashMap lookup for the steady-state case. Falls through to the
///   legacy candidate-length sweep on miss for client / migration / mixed-
///   length deployments.
///
/// **Phase 1**: Match by peer_hash + DCID across candidate lengths 0..20.
/// - Hash table lookup per candidate length (O(L) hashes, L ≤ 21)
/// - Server prioritization: prefer connections with both app RX/TX keys
/// - Tie-break on longer DCID length
///
/// **Phase 1b**: Same-peer iterator fallback for connections registered with
/// only their composite key but advertising additional CIDs in `local_cids`.
///
/// **Phase 2**: NAT rebinding fallback (RFC 9000 §9.3)
/// - If Phase 1 finds nothing, scan all connections by DCID only
/// - Invokes path_changed_fn when NAT rebinding detected
/// - Triggers path validation per RFC 9000 §9.3
///
/// Parameters:
/// - conns: Connection table to search
/// - peer: Peer socket address
/// - packet_bytes: Raw packet bytes (DCID starts at byte 1)
/// - path_changed_fn: Optional callback for NAT rebinding notification
///
/// Returns: LookupResult with connection, DCID length, and rebinding flag
pub fn findConnectionByDcid(
    conns: *std.AutoHashMap(types.Key, *conn_mod.Connection),
    peer: conn_mod.SockAddr,
    packet_bytes: []const u8,
    path_changed_fn: ?OnPathChangedFn,
) LookupResult {
    const peer_h = hashSockaddr(&peer.storage, peer.len);
    var found: ?*conn_mod.Connection = null;
    var dcid_len: usize = 0;

    // Phase 1: Match by peer_hash + DCID (normal operation)
    // Prefer connections with both app RX/TX keys (server prioritization)
    var best: ?*conn_mod.Connection = null;
    var best_len: usize = 0;

    // #154 fast path: try the canonical 8-byte DCID first. Every CID we
    // issue is 8 bytes (`acquireLocalCid` in methods_c.zig), so a single
    // hash lookup typically resolves the routing. We mark `tried_default`
    // so the candidate-length sweep below doesn't repeat the same lookup.
    var tried_default = false;
    if (1 + DEFAULT_DCID_LEN <= packet_bytes.len) {
        tried_default = true;
        const candidate_dcid = packet_bytes[1 .. 1 + DEFAULT_DCID_LEN];
        const key = makeKey(peer_h, hashBytes(candidate_dcid));
        if (conns.getPtr(key)) |entry| {
            const c = entry.*;
            if (c.localDcidMatchLen(packet_bytes, true)) |l| {
                found = c;
                dcid_len = l;
                const has_rx = (c.app_rx_keys != null);
                const has_tx = (c.app_tx_keys != null);
                if (has_rx and has_tx) {
                    best = c;
                    best_len = l;
                }
            }
        }
    }

    var candidate_len: usize = 0;
    while (candidate_len <= 20 and 1 + candidate_len <= packet_bytes.len) : (candidate_len += 1) {
        // Skip the canonical length when the fast path already covered it.
        if (candidate_len == DEFAULT_DCID_LEN and tried_default) continue;
        const candidate_dcid = packet_bytes[1 .. 1 + candidate_len];
        const key = makeKey(peer_h, hashBytes(candidate_dcid));
        const c = (conns.getPtr(key) orelse continue).*;
        const l = c.localDcidMatchLen(packet_bytes, true) orelse continue;

        // Record first match as fallback
        if (found == null) {
            found = c;
            dcid_len = l;
        } else if (l > dcid_len) {
            found = c;
            dcid_len = l;
        }

        // Server prioritization: prefer connections with both app keys
        const has_rx = (c.app_rx_keys != null);
        const has_tx = (c.app_tx_keys != null);
        if (has_rx and has_tx) {
            if (best == null or l > best_len) {
                best = c;
                best_len = l;
            }
        }
    }

    // Use best match if available
    if (best) |b| {
        found = b;
        dcid_len = best_len;
    }

    // Phase 1b: same-peer advertised CID fallback.
    //
    // Most packets are routed through the composite peer+DCID hash key above.
    // Some tests and older issuance paths only register the connection's
    // original DCID key while local_cids contains additional advertised CIDs.
    // Keep those packets on the normal path, but only scan same-peer entries so
    // this does not trigger NAT rebinding side effects.
    if (found == null) {
        var it_same_peer = conns.iterator();
        while (it_same_peer.next()) |entry| {
            if (entry.key_ptr.peer_hash != peer_h) continue;
            const c = entry.value_ptr.*;
            const l = c.localDcidMatchLen(packet_bytes, true) orelse continue;

            if (found == null or l > dcid_len) {
                found = c;
                dcid_len = l;
            }

            const has_rx = (c.app_rx_keys != null);
            const has_tx = (c.app_tx_keys != null);
            if (has_rx and has_tx and (best == null or l > best_len)) {
                best = c;
                best_len = l;
            }
        }
        if (best) |b| {
            found = b;
            dcid_len = best_len;
        }
    }

    // Phase 2: NAT rebinding fallback (RFC 9000 §9.3)
    // If no match with peer_hash, try all connections by DCID only
    if (found == null) {
        var it2 = conns.iterator();
        while (it2.next()) |entry| {
            const c = entry.value_ptr.*;
            const l = c.localDcidMatchLen(packet_bytes, false) orelse continue;

            found = c;
            dcid_len = l;

            // Notify caller of NAT rebinding for path validation
            if (path_changed_fn) |callback| {
                callback(c, peer, peer_h, l) catch |err| {
                    logger.warn("NAT rebinding callback failed: {s}", .{@errorName(err)});
                };
            }

            return LookupResult{
                .conn = found,
                .dcid_len = dcid_len,
                .nat_rebinding = true,
            };
        }
    }

    // Return result (no NAT rebinding if Phase 1 succeeded)
    return LookupResult{
        .conn = found,
        .dcid_len = dcid_len,
        .nat_rebinding = false,
    };
}
