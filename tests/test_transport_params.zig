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
        .ack_delay_exponent = 3,
        .max_ack_delay = 25,
        .max_udp_payload_size = 1450,
        .stateless_reset_token = .{0x11} ** 16,
    };
    const iscid_arr = hex(8, "0011223344556677");
    const rscid_arr = hex(8, "8899aabbccddeeff");
    const iscid = try alloc.dupe(u8, &iscid_arr);
    const rscid = try alloc.dupe(u8, &rscid_arr);
    vals.initial_source_connection_id = iscid;
    vals.retry_source_connection_id = rscid;
    // Preferred address raw minimal dummy fulfilling size constraints
    // Layout: IPv4(4) + port(2) + IPv6(16) + port(2) + CID len(1) + CID(0) + stateless reset token(16) = 41 bytes
    var pref_buf: [41]u8 = undefined;
    @memset(pref_buf[0..], 0);
    const pref = try alloc.dupe(u8, &pref_buf);
    vals.preferred_address_raw = pref;

    const enc = try vals.encode(alloc);
    defer alloc.free(enc);

    const dec = try tp.TransportParams.decode(alloc, enc);
    defer {
        var d = dec;
        d.deinit(alloc);
    }
    // Free owned allocations created for encode inputs
    alloc.free(iscid);
    alloc.free(rscid);
    if (vals.preferred_address_raw) |p| alloc.free(p);

    try std.testing.expect(dec.max_idle_timeout.? == 30000);
    try std.testing.expect(dec.initial_max_data.? == 65536);
    try std.testing.expect(dec.initial_max_stream_data_bidi_local.? == 8192);
    try std.testing.expect(dec.initial_max_stream_data_bidi_remote.? == 4096);
    try std.testing.expect(dec.initial_max_stream_data_uni.? == 2048);
    try std.testing.expect(dec.initial_max_streams_bidi.? == 8);
    try std.testing.expect(dec.initial_max_streams_uni.? == 4);
    try std.testing.expect(dec.disable_active_migration == true);
    try std.testing.expect(dec.active_connection_id_limit.? == 8);
    try std.testing.expect(dec.ack_delay_exponent.? == 3);
    try std.testing.expect(dec.max_ack_delay.? == 25);
    try std.testing.expect(dec.max_udp_payload_size.? == 1450);
    try std.testing.expect(dec.stateless_reset_token.?[0] == 0x11);
    if (dec.initial_source_connection_id) |cid| try std.testing.expectEqual(@as(usize, 8), cid.len) else return error.Missing;
    if (dec.retry_source_connection_id) |cid| try std.testing.expectEqual(@as(usize, 8), cid.len) else return error.Missing;
    if (dec.preferred_address_raw) |p| try std.testing.expectEqual(@as(usize, 41), p.len) else return error.Missing;
}
