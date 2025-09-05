const std = @import("std");
const conn_mod = @import("src/quic/conn.zig");

pub fn main() void {
    const offset = @offsetOf(conn_mod.Connection, "app_tx_keys");
    std.debug.print("Offset of app_tx_keys: {d} (0x{x})\n", .{offset, offset});
}
