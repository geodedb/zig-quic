// RFC 9001 §5.4 / §6 / §6.6 key-update lifecycle coverage exercising the
// production helpers (`deriveNextTrafficSecret`, `setAeadUsageLimits`,
// `maybeTriggerKeyUpdateOnSend`) without spinning up a full TLS handshake.
//
// The integration test surface in `tests/integration/key_update.zig` skips
// these cases pending a real TLS pair; the assertions below close that gap at
// the unit-test layer so regressions in the lifecycle plumbing fail fast.

const std = @import("std");
const ks = @import("quic_tls");
const key_update = @import("quic_key_update");
const endpoint = @import("quic_endpoint");
const packet = @import("quic_packet");

fn seedSecretSha256(byte_seed: u8) ks.Secret {
    var s = ks.Secret.empty();
    s.len = @intCast(ks.digestLength(.sha256));
    for (s.sliceMut(), 0..) |*b, i| {
        b.* = @as(u8, @intCast((i + @as(usize, byte_seed)) & 0xff));
    }
    return s;
}

test "RFC 9001 §6 deriveNextTrafficSecret alternates across two updates" {
    const start = seedSecretSha256(1);

    const phase1 = try key_update.deriveNextTrafficSecret(.sha256, &start);
    try std.testing.expect(!std.mem.eql(u8, start.slice(), phase1.slice()));

    const phase2 = try key_update.deriveNextTrafficSecret(.sha256, &phase1);
    try std.testing.expect(!std.mem.eql(u8, phase1.slice(), phase2.slice()));
    try std.testing.expect(!std.mem.eql(u8, start.slice(), phase2.slice()));

    // Determinism: round-tripping the same input still produces the same output.
    const phase1_again = try key_update.deriveNextTrafficSecret(.sha256, &start);
    try std.testing.expectEqualSlices(u8, phase1.slice(), phase1_again.slice());

    // SHA-384 path must also alternate (different cipher suite secret length).
    var start384 = ks.Secret.empty();
    start384.len = @intCast(ks.digestLength(.sha384));
    for (start384.sliceMut(), 0..) |*b, i| b.* = @as(u8, @intCast(i & 0xff));
    const phase1_384 = try key_update.deriveNextTrafficSecret(.sha384, &start384);
    const phase2_384 = try key_update.deriveNextTrafficSecret(.sha384, &phase1_384);
    try std.testing.expect(!std.mem.eql(u8, start384.slice(), phase1_384.slice()));
    try std.testing.expect(!std.mem.eql(u8, phase1_384.slice(), phase2_384.slice()));
}

test "RFC 9001 §6.6 setAeadUsageLimits writes aead_integrity_limit" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    const c = try ep.connectClient("127.0.0.1:11");

    // Documented RFC 9001 §6.6 default for AES-GCM integrity (2^52).
    try std.testing.expectEqual(@as(u64, 1 << 52), c.aead_integrity_limit);
    const default_conf = c.aead_confidentiality_limit;

    c.setAeadUsageLimits(null, 7);
    try std.testing.expectEqual(@as(u64, 7), c.aead_integrity_limit);
    try std.testing.expectEqual(default_conf, c.aead_confidentiality_limit);

    c.setAeadUsageLimits(123, 456);
    try std.testing.expectEqual(@as(u64, 123), c.aead_confidentiality_limit);
    try std.testing.expectEqual(@as(u64, 456), c.aead_integrity_limit);

    // Passing null leaves prior overrides intact.
    c.setAeadUsageLimits(null, null);
    try std.testing.expectEqual(@as(u64, 123), c.aead_confidentiality_limit);
    try std.testing.expectEqual(@as(u64, 456), c.aead_integrity_limit);
}

test "RFC 9001 §6.6 endpoint config aead_integrity_limit_override flows into connection" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &.{
        .alpn = &[_][]const u8{},
        .aead_integrity_limit_override = 9,
        .aead_confidentiality_limit_override = 11,
    });
    defer ep.deinit();
    const c = try ep.connectClient("127.0.0.1:12");
    try std.testing.expectEqual(@as(u64, 9), c.aead_integrity_limit);
    try std.testing.expectEqual(@as(u64, 11), c.aead_confidentiality_limit);
}

test "RFC 9001 §5.4 maybeTriggerKeyUpdateOnSend toggles tx_key_phase past byte threshold" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    const c = try ep.connectClient("127.0.0.1:13");

    // Seed a deterministic application traffic secret + matching keys so the
    // production trigger has the inputs it expects (see methods_b.zig:1573).
    const seed_secret = seedSecretSha256(2);
    const km = ks.deriveKeyIvHpHash(.sha256, &seed_secret, c.version_v2);
    c.app_tx_secret = seed_secret;
    c.app_tx_keys = packet.AeadKeys{ .key = km.key, .iv = km.iv, .hp = km.hp };
    c.tx_key_phase = false;
    c.tx_update_in_progress = false;
    c.tx_sent_packets_since_key = 0;
    c.tx_sent_bytes_since_key = 0;
    c.disable_auto_key_update = false;

    // Below threshold: phase must remain stable, no update in progress.
    c.maybeTriggerKeyUpdateOnSend(1024);
    try std.testing.expectEqual(false, c.tx_key_phase);
    try std.testing.expectEqual(false, c.tx_update_in_progress);

    // Cross the 1 MiB byte threshold (methods_b.zig:1582) in a single call.
    c.maybeTriggerKeyUpdateOnSend(1024 * 1024);
    try std.testing.expectEqual(true, c.tx_key_phase);
    try std.testing.expectEqual(true, c.tx_update_in_progress);
    try std.testing.expectEqual(@as(u64, 0), c.tx_sent_packets_since_key);
    try std.testing.expectEqual(@as(u64, 0), c.tx_sent_bytes_since_key);
    try std.testing.expect(c.tx_prev_keys != null);
    // app_tx_secret advanced to the next phase secret -- no longer the seed.
    try std.testing.expect(!std.mem.eql(u8, seed_secret.slice(), c.app_tx_secret.?.slice()));
}

test "RFC 9001 §5.4 maybeTriggerKeyUpdateOnSend respects disable_auto_key_update" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    const c = try ep.connectClient("127.0.0.1:14");

    const seed_secret = seedSecretSha256(3);
    const km = ks.deriveKeyIvHpHash(.sha256, &seed_secret, c.version_v2);
    c.app_tx_secret = seed_secret;
    c.app_tx_keys = packet.AeadKeys{ .key = km.key, .iv = km.iv, .hp = km.hp };
    c.tx_key_phase = false;
    c.tx_update_in_progress = false;
    c.disable_auto_key_update = true;

    c.maybeTriggerKeyUpdateOnSend(1024 * 1024 * 4);
    try std.testing.expectEqual(false, c.tx_key_phase);
    try std.testing.expectEqual(false, c.tx_update_in_progress);
}
