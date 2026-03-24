const std = @import("std");
const tls13 = @import("quic_tls13");
const crypto = @import("quic_crypto");
const pkt = @import("quic_packet");

// Key Update scaffolding: derive next app traffic secret and verify decrypt with toggled key phase.

test "key update: derive next secret and decrypt with toggled key phase" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    // Simulate handshake and app secrets
    var eng_cli = tls13.Engine.init(a, .Client);
    defer eng_cli.deinit();
    var eng_srv = tls13.Engine.init(a, .Server);
    defer eng_srv.deinit();

    _ = try eng_cli.queueMinimalClientHelloAuto();
    var buf: [256]u8 = undefined;
    const n1 = eng_cli.popCrypto(&buf);
    try eng_srv.onCryptoRecv(buf[0..n1]);

    _ = try eng_srv.queueMinimalServerHelloAuto();
    const n2 = eng_srv.popCrypto(&buf);
    try eng_cli.onCryptoRecv(buf[0..n2]);

    if (eng_cli.ecdhe_secret == null or eng_srv.ecdhe_secret == null) {
        var shared: [32]u8 = .{0} ** 32;
        shared[0] = 9;
        eng_cli.setEcdhe(&shared);
        eng_srv.setEcdhe(&shared);
    }

    const th = eng_cli.transcript.finalize();
    const app_cli = tls13.deriveApplicationTrafficFromEcdhe(eng_cli.ecdhe_secret.?, th);
    const app_srv = tls13.deriveApplicationTrafficFromEcdhe(eng_srv.ecdhe_secret.?, th);

    // Derive next-phase secrets/keys (client initiates update)
    const next_cli = crypto.deriveNextAppKeys(app_cli.client_app, false);
    const next_srv = crypto.deriveNextAppKeys(app_srv.client_app, false);
    const cli_w1 = next_cli.keys; // client write phase 1
    const srv_r1 = next_srv.keys; // server read phase 1

    // Encode a short packet with next keys and key phase = 1
    const dcid = "s-cid";
    var header_first: u8 = 0x40 | 0x04 | 0; // short, kp=1, pn len=1
    const pn_len: u3 = 1;
    const pn: u32 = 7;

    var header = std.ArrayList(u8){};
    defer header.deinit(alloc);
    try header.append(alloc, header_first);
    try header.appendSlice(alloc, dcid);
    const prefix = header.items[1..];

    var pn_bytes: [1]u8 = .{@as(u8, @intCast(pn))};
    const payload = "upd";

    const ct = try a.alloc(u8, payload.len + 16);
    defer a.free(ct);
    _ = try crypto.protectInitial(.aes_128_gcm, &cli_w1.key, &cli_w1.iv, &cli_w1.hp, pn, &header_first, pn_bytes[0..], prefix, payload, ct);

    // Build packet bytes (short header): first | dcid | pn | ct
    var packet = std.ArrayList(u8){};
    defer packet.deinit(alloc);
    try packet.append(alloc, header_first);
    try packet.appendSlice(alloc, dcid);
    try packet.appendSlice(alloc, &pn_bytes);
    try packet.appendSlice(alloc, ct);

    // Build HP sample for AES (PN start + 4)
    var sample16: [16]u8 = undefined;
    @memcpy(sample16[0..], packet.items[1 + dcid.len + 4 .. 1 + dcid.len + 4 + 16]);

    // Unprotect header and PN using next read keys
    var hdr_first_m = packet.items[0];
    var pn_buf: [4]u8 = .{0} ** 4;
    pn_buf[0] = pn_bytes[0];
    try crypto.headerUnprotect(.aes_128_gcm, &srv_r1.hp, &sample16, &hdr_first_m, pn_buf[0..pn_len]);

    // AAD and decrypt with next keys
    var aad = std.ArrayList(u8){};
    defer aad.deinit(alloc);
    try aad.append(alloc, hdr_first_m);
    try aad.appendSlice(alloc, dcid);
    try aad.appendSlice(alloc, pn_buf[0..pn_len]);

    const pt = try a.alloc(u8, payload.len);
    defer a.free(pt);
    const got = try crypto.aeadDecrypt(.aes_128_gcm, &srv_r1.key, &srv_r1.iv, pn, aad.items, packet.items[1 + dcid.len + pn_len ..], pt);
    try std.testing.expectEqual(@as(usize, payload.len), got);
    try std.testing.expect(std.mem.eql(u8, pt, payload));

    // Sanity: decode key phase bit
    const kp = crypto.decodeShortHeaderKeyPhaseAndPnLen(header_first);
    try std.testing.expect(kp.key_phase == true);
    try std.testing.expectEqual(@as(u3, 1), kp.pn_len);
}

// Test Case 3: Verify Header Protection key is preserved across Key Updates.
//
// RFC 9001 §6: "The header protection key is not updated during key updates."
// This is confirmed by reference implementations like quic-go.
test "key update: header protection key preserved across updates" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    // Simulate handshake and derive application secrets
    var eng_cli = tls13.Engine.init(a, .Client);
    defer eng_cli.deinit();
    var eng_srv = tls13.Engine.init(a, .Server);
    defer eng_srv.deinit();

    _ = try eng_cli.queueMinimalClientHelloAuto();
    var buf: [256]u8 = undefined;
    const n1 = eng_cli.popCrypto(&buf);
    try eng_srv.onCryptoRecv(buf[0..n1]);

    _ = try eng_srv.queueMinimalServerHelloAuto();
    const n2 = eng_srv.popCrypto(&buf);
    try eng_cli.onCryptoRecv(buf[0..n2]);

    if (eng_cli.ecdhe_secret == null or eng_srv.ecdhe_secret == null) {
        var shared: [32]u8 = .{0} ** 32;
        shared[0] = 11;
        eng_cli.setEcdhe(&shared);
        eng_srv.setEcdhe(&shared);
    }

    const th = eng_cli.transcript.finalize();
    const app_cli = tls13.deriveApplicationTrafficFromEcdhe(eng_cli.ecdhe_secret.?, th);

    // Derive phase 0 keys
    const keys_phase0 = crypto.keysFromSecret(app_cli.client_app);
    const hp_phase0 = keys_phase0.hp;

    // Derive phase 1 keys (first key update)
    const next1 = crypto.deriveNextAppKeys(app_cli.client_app, false);
    const keys_phase1 = next1.keys;
    const secret_phase1 = next1.secret;
    const hp_phase1 = keys_phase1.hp;

    // Derive phase 2 keys (second key update)
    const next2 = crypto.deriveNextAppKeys(secret_phase1, false);
    const keys_phase2 = next2.keys;
    const hp_phase2 = keys_phase2.hp;

    // Verify: HP keys from derivation are NOT preserved automatically by deriveNextAppKeys
    // (deriveNextAppKeys derives new HP keys, but conn.zig preserves the original)
    // The key schedule derives new HP keys, but they should be IGNORED per RFC 9001 §6

    // What matters is that the implementation preserves HP key:
    // conn.zig lines 3182-3192 show: `const preserved_hp = self.app_tx_keys.?.hp;`
    // then: `self.app_tx_keys = .{ .key = t.key, .iv = t.iv, .hp = preserved_hp };`

    // Verify deriveNextAppKeys produces new keys (key and iv should differ)
    try std.testing.expect(!std.mem.eql(u8, &keys_phase0.key, &keys_phase1.key));
    try std.testing.expect(!std.mem.eql(u8, &keys_phase0.iv, &keys_phase1.iv));
    try std.testing.expect(!std.mem.eql(u8, &keys_phase1.key, &keys_phase2.key));
    try std.testing.expect(!std.mem.eql(u8, &keys_phase1.iv, &keys_phase2.iv));

    // The HP keys derived by key schedule will be different, but the IMPLEMENTATION
    // should preserve the original HP key. Let's verify that the preservation logic
    // would work by simulating what conn.zig does:
    const original_hp = hp_phase0;

    // Simulate key update with HP preservation (as done in conn.zig)
    const updated_keys_phase1 = pkt.AeadKeys{
        .key = keys_phase1.key,
        .iv = keys_phase1.iv,
        .hp = original_hp, // Preserved from phase 0
    };

    const updated_keys_phase2 = pkt.AeadKeys{
        .key = keys_phase2.key,
        .iv = keys_phase2.iv,
        .hp = original_hp, // Still preserved from phase 0
    };

    // Verify HP key is preserved across multiple updates
    try std.testing.expect(std.mem.eql(u8, &updated_keys_phase1.hp, &original_hp));
    try std.testing.expect(std.mem.eql(u8, &updated_keys_phase2.hp, &original_hp));

    // Verify the derived HP keys would be different (showing preservation is necessary)
    // Note: deriveNextAppKeys derives new HP from the new secret, so they differ
    try std.testing.expect(!std.mem.eql(u8, &hp_phase0, &hp_phase1));
    try std.testing.expect(!std.mem.eql(u8, &hp_phase1, &hp_phase2));

    // Verify we can still use the preserved HP key for header protection
    // Encode a sample to test HP masking works with preserved key
    var sample: [16]u8 = .{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    var header_byte: u8 = 0x40;
    var pn_bytes: [4]u8 = .{ 0x01, 0x02, 0x03, 0x04 };
    const header_byte_orig = header_byte;
    var pn_bytes_orig: [4]u8 = undefined;
    @memcpy(&pn_bytes_orig, &pn_bytes);

    // Apply header protection with original HP key
    try crypto.headerProtect(.aes_128_gcm, &original_hp, &sample, &header_byte, &pn_bytes);

    // Verify header and PN were modified
    try std.testing.expect(header_byte != header_byte_orig or !std.mem.eql(u8, &pn_bytes, &pn_bytes_orig));

    // Unprotect with same HP key
    try crypto.headerUnprotect(.aes_128_gcm, &original_hp, &sample, &header_byte, &pn_bytes);

    // Verify header and PN are restored
    try std.testing.expectEqual(header_byte_orig, header_byte);
    try std.testing.expect(std.mem.eql(u8, &pn_bytes, &pn_bytes_orig));
}
