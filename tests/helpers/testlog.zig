const std = @import("std");

var cached_enabled: i8 = -1;
var cache_mu: std.Io.Mutex = .init;

fn resolveEnabled() bool {
    const env_ptr = std.c.getenv("QUIC_TEST_VERBOSE") orelse return false;
    const env_val = std.mem.span(env_ptr);
    return env_val.len != 0 and !std.mem.eql(u8, env_val, "0");
}

pub fn enabled() bool {
    if (cached_enabled != -1) return cached_enabled == 1;
    const io = std.Io.Threaded.global_single_threaded.io();
    cache_mu.lockUncancelable(io);
    defer cache_mu.unlock(io);
    if (cached_enabled == -1) {
        cached_enabled = if (resolveEnabled()) 1 else 0;
    }
    return cached_enabled == 1;
}

pub fn print(comptime fmt: []const u8, args: anytype) void {
    if (enabled()) {
        std.debug.print(fmt, args);
    }
}
