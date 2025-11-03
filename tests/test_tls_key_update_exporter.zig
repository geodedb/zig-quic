const std = @import("std");
const tls13 = @import("quic_tls13");
const ks = @import("quic_tls");

test "exporter produces stable prefix after application secrets" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){}; defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    var ctx = tls13.Context.init(.{ .allocator = alloc, .role = .Client }, .{});
    defer ctx.deinit();
    const dummy_hs: [ks.H.digest_length]u8 = .{0x11} ** ks.H.digest_length;
    try ctx.installTrafficSecret(.Handshake, .send, dummy_hs);
    try ctx.installTrafficSecret(.Handshake, .recv, dummy_hs);
    const dummy_app: [ks.H.digest_length]u8 = .{0x22} ** ks.H.digest_length;
    try ctx.installTrafficSecret(.Application, .send, dummy_app);
    try ctx.installTrafficSecret(.Application, .recv, dummy_app);
    // Manually set exporter_master since we're not running full handshake
    ctx.secrets.exporter_master.store(.Application, dummy_app);
    ctx.transcripts.finished_hash = dummy_app;
    var out1: [32]u8 = undefined; try ctx.exportSecret("test label", &out1);
    var out2: [32]u8 = undefined; try ctx.exportSecret("test label", &out2);
    try std.testing.expectEqualSlices(u8, out1[0..], out2[0..]);
}

test "key update rotates send and recv secrets" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){}; defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    var ctx = tls13.Context.init(.{ .allocator = alloc, .role = .Client }, .{});
    defer ctx.deinit();
    const init_secret: [ks.H.digest_length]u8 = .{0x33} ** ks.H.digest_length;
    try ctx.installTrafficSecret(.Application, .send, init_secret);
    try ctx.installTrafficSecret(.Application, .recv, init_secret);
    const send_before = ctx.secrets.slot(.Application, .send).value;
    const recv_before = ctx.secrets.slot(.Application, .recv).value;
    try ctx.performKeyUpdateSend();
    try ctx.performKeyUpdateRecv();
    const send_after = ctx.secrets.slot(.Application, .send).value;
    const recv_after = ctx.secrets.slot(.Application, .recv).value;
    try std.testing.expect(!std.mem.eql(u8, send_before[0..], send_after[0..]));
    try std.testing.expect(!std.mem.eql(u8, recv_before[0..], recv_after[0..]));
    try std.testing.expect(ctx.secrets.slot(.Application, .send).generation == 2);
    try std.testing.expect(ctx.secrets.slot(.Application, .recv).generation == 2);
}
