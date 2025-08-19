const std = @import("std");
const tp = @import("quic_transport_params");

fn hex(comptime N: usize, s: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    var i: usize = 0;
    var j: usize = 0;
    while (i + 1 < s.len and j < N) : ({
        i += 2;
        j += 1;
    }) {
        const hi = std.fmt.charToDigit(s[i], 16) catch 0;
        const lo = std.fmt.charToDigit(s[i + 1], 16) catch 0;
        out[j] = @as(u8, @intCast(hi * 16 + lo));
    }
    return out;
}

test "transport parameters encode/decode roundtrip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var vals: tp.TransportParams = .{
        .max_idle_timeout = 30000,
        .initial_max_data = 65536,
        .initial_max_stream_data_bidi_local = 8192,
        .initial_max_stream_data_bidi_remote = 4096,
        .initial_max_stream_data_uni = 2048,
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 4,
        .disable_active_migration = true,
        .active_connection_id_limit = 8,
    };

    const enc = try vals.encode(alloc);
    defer alloc.free(enc);

    const dec = try tp.TransportParams.decode(alloc, enc);
    defer {
        var d = dec;
        d.deinit(alloc);
    }

    try std.testing.expect(dec.max_idle_timeout.? == 30000);
    try std.testing.expect(dec.initial_max_data.? == 65536);
    try std.testing.expect(dec.initial_max_stream_data_bidi_local.? == 8192);
    try std.testing.expect(dec.initial_max_stream_data_bidi_remote.? == 4096);
    try std.testing.expect(dec.initial_max_stream_data_uni.? == 2048);
    try std.testing.expect(dec.initial_max_streams_bidi.? == 8);
    try std.testing.expect(dec.initial_max_streams_uni.? == 4);
    try std.testing.expect(dec.disable_active_migration == true);
    try std.testing.expect(dec.active_connection_id_limit.? == 8);
}
