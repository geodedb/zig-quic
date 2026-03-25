// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Connection Lifecycle Management (RFC 9000 §10)
//!
//! This module handles connection lifecycle operations:
//! - Stale connection detection and closure
//! - Closed connection pruning from tables
//! - Connection retirement and cleanup
//! - Timer and CID table cleanup
//!
//! RFC References:
//! - RFC 9000 §10: Connection Termination
//! - RFC 9000 §10.2: Idle Timeout
//! - RFC 9000 §10.3: Immediate Close
//! - RFC 9000 §5.1: Connection ID Management
//!
//! Phase 10: Extract connection lifecycle management from endpoint.zig

const std = @import("std");
const logger = @import("quic_logger");
const conn_mod = @import("quic_conn");
const types = @import("types");

// Use canonical Timer from types.zig (endpoint/types.zig)
const Timer = types.Timer;

/// Context for lifecycle operations.
/// Focused context pattern - only includes what's needed for lifecycle management.
pub const LifecycleContext = struct {
    /// Memory allocator
    allocator: std.mem.Allocator,
    /// Connection table (key -> connection)
    conns: *std.AutoHashMap(types.Key, *conn_mod.Connection),
    /// Timer queue (uses generic ArrayList pointer to avoid type conflicts)
    timers: *anyopaque,
    /// Retired connections list
    retired: *std.ArrayList(*conn_mod.Connection),

    /// Helper to get timers as the correct type
    fn getTimers(self: *const LifecycleContext) *std.ArrayList(Timer) {
        return @ptrCast(@alignCast(self.timers));
    }
};

// =============================================================================
// Module Status and Documentation
// =============================================================================

/// Module marker for Phase 10.
/// Connection lifecycle management has been extracted from endpoint.zig.
pub const extracted = true;

/// Module version for documentation
pub const version = "Phase 10 - Connection Lifecycle Extraction";

// =============================================================================
// Utility Functions
// =============================================================================

/// Hash a sockaddr for peer comparison.
/// Extracted from endpoint.zig to support stale connection detection.
fn hashSockaddr(storage: *const std.posix.sockaddr.storage, len: std.posix.socklen_t) u64 {
    const bytes = @as([*]const u8, @ptrCast(storage))[0..len];
    return std.hash.Wyhash.hash(0, bytes);
}

// =============================================================================
// Stale Connection Detection (RFC 9000 §10)
// =============================================================================

/// Close stale connections from the same peer when a new connection is established.
/// Extracted from endpoint.zig:2723-2785 (Phase 10).
///
/// RFC 9000 §10: When a new connection is established from a peer, older connections
/// from the same peer should be closed to prevent resource exhaustion and connection
/// confusion.
///
/// This function:
/// 1. Identifies all connections from the same peer (by sockaddr hash)
/// 2. Excludes the new connection being established
/// 3. Sends CONNECTION_CLOSE to stale connections
/// 4. Marks them as closed for pruning
///
/// Note: Only runs after handshake completion (app_rx_keys != null) to avoid
/// closing connections prematurely during handshake.
pub fn closeStaleConnectionsForPeer(ctx: *LifecycleContext, new_conn: *conn_mod.Connection) void {
    // Only run after handshake complete to avoid premature closure
    if (new_conn.app_rx_keys == null) return;

    const peer_hash = hashSockaddr(&new_conn.peer.storage, new_conn.peer.len);

    // Collect connections to close
    var to_close = std.ArrayList(*conn_mod.Connection){};
    defer to_close.deinit(ctx.allocator);

    // Find all connections from same peer
    var it = ctx.conns.iterator();
    while (it.next()) |e| {
        const c = e.value_ptr.*;
        if (c == new_conn) continue; // Skip the new connection

        const c_peer_hash = hashSockaddr(&c.peer.storage, c.peer.len);
        if (c_peer_hash != peer_hash) continue;

        // Mark for closure
        to_close.append(ctx.allocator, c) catch continue;
    }

    // Close all stale connections with appropriate error message
    for (to_close.items) |c| {
        c.sendConnectionClose(0x00, "Replaced by new connection from same peer") catch |err| {
            logger.warn("sendConnectionClose for stale conn failed: {s}", .{@errorName(err)});
        };
        c.closed = true;
    }
}

// =============================================================================
// Connection Pruning (RFC 9000 §10)
// =============================================================================

/// Prune closed connections from connection table and timer queue.
/// Extracted from endpoint.zig:2787-2840 (Phase 10).
///
/// RFC 9000 §10: After a connection is closed, it should be removed from active
/// connection tables and timer queues, but retained temporarily to handle any
/// late-arriving packets.
///
/// This function:
/// 1. Collects all closed connections
/// 2. Removes them from the connection table (conns HashMap)
/// 3. Cancels their pending timers
/// 4. Moves them to the retired list for deferred cleanup
///
/// Retired connections are kept for a draining period before final deallocation.
pub fn pruneClosed(ctx: *LifecycleContext) void {
    // Collect keys referencing closed connections
    var keys = std.ArrayList(types.Key){};
    defer keys.deinit(ctx.allocator);

    var closed_set = std.AutoHashMap(*conn_mod.Connection, void).init(ctx.allocator);
    defer closed_set.deinit();

    // Find all closed connections
    var it = ctx.conns.iterator();
    while (it.next()) |e| {
        const c = e.value_ptr.*;
        if (c.closed) {
            closed_set.put(c, {}) catch continue;
            keys.append(ctx.allocator, e.key_ptr.*) catch |err| {
                logger.err("pruneClosedConnections: keys.append failed (OOM): {s}", .{@errorName(err)});
            };
        }
    }

    if (closed_set.count() == 0) return;

    // Remove from connection table
    for (keys.items) |k| {
        _ = ctx.conns.remove(k);
    }

    // Cancel timers for closed connections
    const timers = ctx.getTimers();
    var ti: usize = 0;
    while (ti < timers.items.len) {
        const t = timers.items[ti];
        if (t.conn) |tc| {
            if (closed_set.contains(tc)) {
                // Free paced packet payload if present
                if (t.paced) {
                    if (t.payload) |p| ctx.allocator.free(p);
                }
                _ = timers.orderedRemove(ti);
                continue; // Don't increment ti, check same index again
            }
        }
        ti += 1;
    }

    // Move to retired list for draining period
    var cit = closed_set.iterator();
    while (cit.next()) |ce| {
        const cptr = ce.key_ptr.*;

        // Check if already retired (avoid duplicates)
        var already = false;
        for (ctx.retired.items) |r| {
            if (r == cptr) {
                already = true;
                break;
            }
        }

        if (!already) {
            ctx.retired.append(ctx.allocator, cptr) catch |err| {
                logger.err("retired.append failed (OOM): {s}", .{@errorName(err)});
            };
        }
    }
}

// =============================================================================
// Connection Retirement and Destruction
// =============================================================================

/// Retire a single connection immediately.
/// Moves a connection from active to retired state without waiting for pruning.
///
/// Use this when you need immediate retirement, e.g., during graceful shutdown.
pub fn retireConnection(ctx: *LifecycleContext, conn: *conn_mod.Connection) void {
    // Mark as closed if not already
    if (!conn.closed) {
        conn.closed = true;
    }

    // Remove from connection table
    var it = ctx.conns.iterator();
    while (it.next()) |e| {
        if (e.value_ptr.* == conn) {
            _ = ctx.conns.remove(e.key_ptr.*);
            break;
        }
    }

    // Cancel timers
    const timers = ctx.getTimers();
    var ti: usize = 0;
    while (ti < timers.items.len) {
        const t = timers.items[ti];
        if (t.conn) |tc| {
            if (tc == conn) {
                if (t.paced) {
                    if (t.payload) |p| ctx.allocator.free(p);
                }
                _ = timers.orderedRemove(ti);
                continue;
            }
        }
        ti += 1;
    }

    // Add to retired list
    var already = false;
    for (ctx.retired.items) |r| {
        if (r == conn) {
            already = true;
            break;
        }
    }

    if (!already) {
        ctx.retired.append(ctx.allocator, conn) catch |err| {
            logger.err("retireConnection: retired.append failed (OOM): {s}", .{@errorName(err)});
        };
    }
}

/// Destroy a retired connection and free its resources.
/// Final cleanup step - deallocates the connection struct itself.
///
/// This should only be called after the draining period expires.
pub fn destroyConnection(ctx: *LifecycleContext, conn: *conn_mod.Connection) void {
    // Call connection's deinit to free internal resources
    conn.deinit();

    // Remove from retired list
    for (ctx.retired.items, 0..) |r, i| {
        if (r == conn) {
            // PERF-P2b: O(1) removal — retired list order is not significant.
            _ = ctx.retired.swapRemove(i);
            break;
        }
    }

    // Finally, free the connection struct itself
    ctx.allocator.destroy(conn);
}

// =============================================================================
// Lifecycle State Queries
// =============================================================================

/// Count total connections in all states (active + retired).
pub fn totalConnectionCount(ctx: *const LifecycleContext) usize {
    return ctx.conns.count() + ctx.retired.items.len;
}

/// Count only active connections (not retired).
pub fn activeConnectionCount(ctx: *const LifecycleContext) usize {
    return ctx.conns.count();
}

/// Count retired connections awaiting destruction.
pub fn retiredConnectionCount(ctx: *const LifecycleContext) usize {
    return ctx.retired.items.len;
}
