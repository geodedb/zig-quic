const std = @import("std");

var cached_enabled: i8 = -1;
var cache_mu = std.Thread.Mutex{};

fn resolveEnabled() bool {
    const env_val = std.process.getEnvVarOwned(std.heap.page_allocator, "QUIC_TEST_VERBOSE") catch return false;
    defer std.heap.page_allocator.free(env_val);
    return env_val.len != 0 and !std.mem.eql(u8, env_val, "0");
}

pub fn enabled() bool {
    if (cached_enabled != -1) return cached_enabled == 1;
    cache_mu.lock();
    defer cache_mu.unlock();
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
