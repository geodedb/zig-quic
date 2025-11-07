//! Connection lookup and routing.
//!
//! RFC 9000 §5.1: Connection ID Routing
//! RFC 9000 §5.2: Matching Packets to Connections

const std = @import("std");
const types = @import("types.zig");
const conn_mod = @import("../conn.zig");

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
