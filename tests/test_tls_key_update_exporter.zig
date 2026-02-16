const std = @import("std");
const tls13 = @import("quic_tls13");
const ks = @import("quic_tls");

// RFC 8446 §7.5 defines the TLS exporter interface, while §7.2 describes Key
// Update. Confirm exporter stability once application secrets are installed and
// that performKeyUpdate rotates send/receive traffic secrets as mandated.
test "exporter produces stable prefix after application secrets" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    var ctx = try tls13.Context.init(.{ .allocator = alloc, .role = .Client }, .{});
    defer ctx.deinit();
    const dummy_hs: [ks.H.digest_length]u8 = .{0x11} ** ks.H.digest_length;
    const dummy_hs_secret = ks.Secret.fromSlice(.sha256, &dummy_hs);
    try ctx.installTrafficSecret(.Handshake, .send, dummy_hs_secret);
    try ctx.installTrafficSecret(.Handshake, .recv, dummy_hs_secret);
    const dummy_app: [ks.H.digest_length]u8 = .{0x22} ** ks.H.digest_length;
    const dummy_app_secret = ks.Secret.fromSlice(.sha256, &dummy_app);
    try ctx.installTrafficSecret(.Application, .send, dummy_app_secret);
    try ctx.installTrafficSecret(.Application, .recv, dummy_app_secret);
    // Manually set exporter_master since we're not running full handshake
    ctx.secrets.exporter_master.store(.Application, .sha256, dummy_app_secret);
    // ctx.transcripts.finished_hash expects HashDigestCache, which is complex to construct for testing
    var out1: [32]u8 = undefined;
    try ctx.exportSecret("test label", &out1);
    var out2: [32]u8 = undefined;
    try ctx.exportSecret("test label", &out2);
    try std.testing.expectEqualSlices(u8, out1[0..], out2[0..]);
}

test "key update rotates send and recv secrets" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    var ctx = try tls13.Context.init(.{ .allocator = alloc, .role = .Client }, .{});
    defer ctx.deinit();
    const init_secret: [ks.H.digest_length]u8 = .{0x33} ** ks.H.digest_length;
    const init_secret_wrap = ks.Secret.fromSlice(.sha256, &init_secret);
    try ctx.installTrafficSecret(.Application, .send, init_secret_wrap);
    try ctx.installTrafficSecret(.Application, .recv, init_secret_wrap);
    const send_before = ctx.secrets.slot(.Application, .send).value;
    const recv_before = ctx.secrets.slot(.Application, .recv).value;
    try ctx.performKeyUpdateSend();
    try ctx.performKeyUpdateRecv();
    const send_after = ctx.secrets.slot(.Application, .send).value;
    const recv_after = ctx.secrets.slot(.Application, .recv).value;
    try std.testing.expect(!std.mem.eql(u8, send_before.slice(), send_after.slice()));
    try std.testing.expect(!std.mem.eql(u8, recv_before.slice(), recv_after.slice()));
    try std.testing.expect(ctx.secrets.slot(.Application, .send).generation == 2);
    try std.testing.expect(ctx.secrets.slot(.Application, .recv).generation == 2);
}
