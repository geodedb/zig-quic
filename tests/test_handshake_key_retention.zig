// SPDX-License-Identifier: Apache-2.0
const std = @import("std");
const testing = std.testing;
const conn_mod = @import("quic_conn");
const handshake = @import("handshake_integration");
const ks = @import("quic_tls");

const Installer = enum { connection, callback };

fn install(c: *conn_mod.Connection, installer: Installer) !void {
    const client = ks.Secret.fromSlice(.sha256, &([_]u8{0x31} ** 32));
    const server = ks.Secret.fromSlice(.sha256, &([_]u8{0x52} ** 32));
    switch (installer) {
        .connection => c.deriveAppKeys(client, server, false),
        .callback => try handshake.installApplicationKeys(c, client, server),
    }
}

fn prepare(c: *conn_mod.Connection, allocator: *std.mem.Allocator, role: conn_mod.Role) !void {
    c.init(allocator, role, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    c.version = 1;
    c.handshake_packet_sent = true;
    c.peer_finished_verified = true;
    c.hs_tx_keys = .{ .key = .{0x11} ** 16, .iv = .{0x22} ** 12, .hp = .{0x33} ** 16 };
    c.hs_rx_keys = c.hs_tx_keys;
    c.crypto_retx_handshake = try allocator.dupe(u8, "client Finished CRYPTO");
    c.crypto_retx_handshake_off = 7;
    c.crypto_tx_off_handshake = 7 + c.crypto_retx_handshake.?.len;
    c.pto_handshake_active = true;
    c.pto_handshake_id = 123;
    c.pto_handshake_count = 2;
}

fn expectUnconfirmedClientRetains(installer: Installer) !void {
    var allocator = testing.allocator;
    var c: conn_mod.Connection = undefined;
    try prepare(&c, &allocator, .Client);
    defer c.deinit();
    try install(&c, installer);

    try testing.expect(c.app_tx_keys != null);
    try testing.expect(c.hs_tx_keys != null and c.hs_rx_keys != null);
    try testing.expectEqualStrings("client Finished CRYPTO", c.crypto_retx_handshake.?);
    try testing.expectEqual(@as(u64, 7), c.crypto_retx_handshake_off);
    try testing.expect(c.pto_handshake_active);
    try testing.expectEqual(@as(u64, 123), c.pto_handshake_id);
    try testing.expectEqual(@as(u32, 2), c.pto_handshake_count);
}

test "client application keys preserve Handshake recovery until server confirmation via connection" {
    try expectUnconfirmedClientRetains(.connection);
}

test "client application keys preserve Handshake recovery until server confirmation via callback" {
    try expectUnconfirmedClientRetains(.callback);
}

const LossCapture = struct {
    attempts: usize = 0,
    delivered_bytes: usize = 0,
    last_packet: [2048]u8 = undefined,
    last_packet_len: usize = 0,

    fn send(raw: *anyopaque, _: *conn_mod.Connection, data: []const u8) !usize {
        const self: *LossCapture = @ptrCast(@alignCast(raw));
        // Only count v1 Handshake packets. The legacy installer can also
        // advertise application flow control; those packets are not recovery.
        if (data.len > 0 and data[0] & 0xf0 == 0xe0) {
            self.attempts += 1;
            // Drop the first datagram after successful transport submission.
            if (self.attempts > 1) {
                if (data.len > self.last_packet.len) return error.TestPacketTooLarge;
                @memcpy(self.last_packet[0..data.len], data);
                self.last_packet_len = data.len;
                self.delivered_bytes += data.len;
            }
        }
        return data.len;
    }
};

fn expectDeliveredCrypto(c: *conn_mod.Connection, capture: *const LossCapture, expected: []const u8, offset: u64) !void {
    const bytes = capture.last_packet[0..capture.last_packet_len];
    try testing.expect(bytes.len >= 7);
    var i: usize = 5;
    i += 1 + bytes[i]; // DCID
    i += 1 + bytes[i]; // SCID
    const length = try @import("quic_varint").decode(bytes[i..]);
    i += length.n;
    try testing.expect(i + 20 <= bytes.len);
    const sample: [16]u8 = bytes[i + 4 ..][0..16].*;
    var first = bytes[0];
    var pn: [4]u8 = bytes[i..][0..4].*;
    var first_tmp = first;
    var pn_tmp = pn;
    const keys = c.hs_tx_keys.?;
    const crypto = @import("quic_crypto");
    const pn_len = try crypto.unmaskLongHeaderAndPn(.aes_128_gcm, &keys.hp, &sample, &first_tmp, &pn_tmp);
    const ciphertext = bytes[i + pn_len .. i + @as(usize, @intCast(length.value))];
    try testing.expect(ciphertext.len >= 16);
    const plaintext = try testing.allocator.alloc(u8, ciphertext.len - 16);
    defer testing.allocator.free(plaintext);
    _ = try crypto.unprotectInitial(.aes_128_gcm, &keys.key, &keys.iv, &keys.hp, &first, pn[0..pn_len], bytes[1..i], &sample, ciphertext, plaintext, 0);
    const decoded = try @import("quic_frame").decodeOne(plaintext);
    try testing.expect(decoded.f == .crypto);
    try testing.expectEqual(offset, decoded.f.crypto.offset);
    try testing.expectEqualStrings(expected, decoded.f.crypto.data);
}

fn expectLostFinishedRetransmits(installer: Installer) !void {
    var allocator = testing.allocator;
    var c: conn_mod.Connection = undefined;
    try prepare(&c, &allocator, .Client);
    defer c.deinit();
    var capture = LossCapture{};
    c.sender_ctx = &capture;
    c.sender_fn = LossCapture.send;
    try install(&c, installer);
    const before = c.pn_handshake_tx;
    c.sendPtoProbeHandshake();
    c.sendPtoProbeHandshake();
    try testing.expectEqual(@as(usize, 2), capture.attempts);
    try testing.expect(capture.delivered_bytes > 0);
    try testing.expectEqual(before + 2, c.pn_handshake_tx);
    try testing.expectEqualStrings("client Finished CRYPTO", c.crypto_retx_handshake.?);
    try expectDeliveredCrypto(&c, &capture, "client Finished CRYPTO", 7);
}

test "lost client Finished remains retransmittable after application key installation via connection" {
    try expectLostFinishedRetransmits(.connection);
}

test "lost client Finished remains retransmittable after application key installation via callback" {
    try expectLostFinishedRetransmits(.callback);
}

test "sending client Finished retains the actual CRYPTO bytes for loss recovery" {
    var allocator = testing.allocator;
    var c: conn_mod.Connection = undefined;
    try prepare(&c, &allocator, .Client);
    defer c.deinit();
    allocator.free(c.crypto_retx_handshake.?);
    c.crypto_retx_handshake = null;
    c.crypto_retx_handshake_off = 0;
    c.crypto_tx_off_handshake = 0;
    var capture = LossCapture{};
    c.sender_ctx = &capture;
    c.sender_fn = LossCapture.send;

    // This is the send path used by pushCrypto for the client's Finished.
    // The transport accepts but drops the first datagram.
    try c.sendHandshakeCrypto("Finished from TLS");
    try install(&c, .connection);
    try testing.expect(c.crypto_retx_handshake != null);
    try testing.expectEqualStrings("Finished from TLS", c.crypto_retx_handshake.?);
    c.sendPtoProbeHandshake();
    try testing.expectEqual(@as(usize, 2), capture.attempts);
    try testing.expect(capture.delivered_bytes > 0);

    // Authenticate and decrypt the delivered retry: it must carry the Finished
    // CRYPTO bytes, not merely a PING that happens to use Handshake keys.
    try expectDeliveredCrypto(&c, &capture, "Finished from TLS", 0);

    // A subsequent CRYPTO chunk cannot erase an unacknowledged earlier one.
    try c.sendHandshakeCrypto(" suffix");
    try testing.expectEqualStrings("Finished from TLS suffix", c.crypto_retx_handshake.?);
    try testing.expectEqual(@as(u64, 0), c.crypto_retx_handshake_off);
}

const RejectedSend = struct {
    short_write: bool,
    attempts: usize = 0,

    fn send(raw: *anyopaque, _: *conn_mod.Connection, data: []const u8) !usize {
        const self: *RejectedSend = @ptrCast(@alignCast(raw));
        self.attempts += 1;
        if (self.short_write) return data.len - 1;
        return error.InjectedSendFailure;
    }
};

fn expectRejectedSendPreservesRecovery(short_write: bool) !void {
    var allocator = testing.allocator;
    var c: conn_mod.Connection = undefined;
    try prepare(&c, &allocator, .Client);
    defer c.deinit();
    var rejected = RejectedSend{ .short_write = short_write };
    c.sender_ctx = &rejected;
    c.sender_fn = RejectedSend.send;
    c.handshake_packet_sent = false;
    const previous = c.crypto_retx_handshake.?;
    const offset = c.crypto_tx_off_handshake;
    const pn = c.pn_handshake_tx;
    try testing.expectError(if (short_write) error.ShortWrite else error.SendFailed, c.sendHandshakeCrypto(" suffix"));
    try testing.expectEqual(@as(usize, 1), rejected.attempts);
    try testing.expect(previous.ptr == c.crypto_retx_handshake.?.ptr);
    try testing.expectEqualStrings("client Finished CRYPTO", c.crypto_retx_handshake.?);
    try testing.expectEqual(offset, c.crypto_tx_off_handshake);
    try testing.expectEqual(pn, c.pn_handshake_tx);
    try testing.expect(!c.handshake_packet_sent);
    try testing.expectEqual(@as(u64, 7), c.crypto_retx_handshake_off);
    try testing.expectEqual(@as(u64, 123), c.pto_handshake_id);
}

test "Handshake CRYPTO send failure preserves retained flight and packet accounting" {
    try expectRejectedSendPreservesRecovery(false);
}

test "Handshake CRYPTO short write preserves retained flight and packet accounting" {
    try expectRejectedSendPreservesRecovery(true);
}

const BlockedSend = struct {
    blocked: bool = true,
    short_write: bool = false,
    permanent_failure: bool = false,
    attempts: usize = 0,

    fn send(raw: *anyopaque, _: *conn_mod.Connection, data: []const u8) !usize {
        const self: *BlockedSend = @ptrCast(@alignCast(raw));
        self.attempts += 1;
        if (self.blocked) return error.WouldBlock;
        if (self.permanent_failure) return error.InjectedSendFailure;
        if (self.short_write) return data.len - 1;
        return data.len;
    }
};

test "client Finished retains pending ownership across repeated blocked submissions" {
    var allocator = testing.allocator;
    var c: conn_mod.Connection = undefined;
    try prepare(&c, &allocator, .Client);
    defer c.deinit();
    var tls_ctx = try handshake.createTlsContext(allocator, .Client, &.{"h3"}, &.{}, null, null, false, false, null, null, null);
    defer tls_ctx.deinit();
    c.tls_context = &tls_ctx;
    defer c.tls_context = null;
    var sender = BlockedSend{};
    c.setSender(&sender, BlockedSend.send);
    c.pending_hs_messages = try allocator.dupe(u8, " suffix");
    const pending = c.pending_hs_messages.?;
    const retained = c.crypto_retx_handshake.?;
    const offset = c.crypto_tx_off_handshake;
    const pn = c.pn_handshake_tx;
    for (0..2) |_| {
        try c.flushClientHandshakeCrypto();
        try testing.expect(c.pending_hs_send);
        try testing.expect(c.pending_hs_messages.?.ptr == pending.ptr);
        try testing.expectEqualStrings(" suffix", c.pending_hs_messages.?);
        try testing.expect(c.crypto_retx_handshake.?.ptr == retained.ptr);
        try testing.expectEqual(offset, c.crypto_tx_off_handshake);
        try testing.expectEqual(pn, c.pn_handshake_tx);
        try testing.expect(!tls_ctx.flags.local_finished_sent);
        try testing.expect(c.app_tx_keys == null);
    }
    sender.blocked = false;
    try c.flushClientHandshakeCrypto();
    try testing.expect(!c.pending_hs_send);
    try testing.expect(c.pending_hs_messages == null);
    try testing.expectEqualStrings("client Finished CRYPTO suffix", c.crypto_retx_handshake.?);
    try testing.expectEqual(offset + pending.len, c.crypto_tx_off_handshake);
    try testing.expectEqual(pn + 1, c.pn_handshake_tx);
    try testing.expect(tls_ctx.flags.local_finished_sent);
    try c.flushClientHandshakeCrypto();
    try testing.expectEqual(@as(usize, 3), sender.attempts);
}

test "client Finished permanent and short send failures preserve pending bytes without retrying" {
    for ([_]bool{ false, true }) |short_write| {
        var allocator = testing.allocator;
        var c: conn_mod.Connection = undefined;
        try prepare(&c, &allocator, .Client);
        defer c.deinit();
        var tls_ctx = try handshake.createTlsContext(allocator, .Client, &.{"h3"}, &.{}, null, null, false, false, null, null, null);
        defer tls_ctx.deinit();
        c.tls_context = &tls_ctx;
        defer c.tls_context = null;
        var sender = BlockedSend{ .blocked = false, .short_write = short_write, .permanent_failure = !short_write };
        c.setSender(&sender, BlockedSend.send);
        c.pending_hs_messages = try allocator.dupe(u8, " suffix");
        const pending = c.pending_hs_messages.?;
        c.pending_hs_send = true;
        const offset = c.crypto_tx_off_handshake;
        const pn = c.pn_handshake_tx;
        try testing.expectError(if (short_write) error.ShortWrite else error.SendFailed, c.flushClientHandshakeCrypto());
        try testing.expect(c.pending_hs_messages.?.ptr == pending.ptr);
        try testing.expectEqualStrings(" suffix", c.pending_hs_messages.?);
        try testing.expectEqualStrings("client Finished CRYPTO", c.crypto_retx_handshake.?);
        try testing.expectEqual(offset, c.crypto_tx_off_handshake);
        try testing.expectEqual(pn, c.pn_handshake_tx);
        try testing.expect(!tls_ctx.flags.local_finished_sent);
        try testing.expect(!c.pending_hs_send);
        try testing.expect(c.app_tx_keys == null);
    }
}

test "Handshake CRYPTO allocation failures preserve recovery and prevent submission" {
    // Fail retention allocation, then packet encoding allocation. Both must
    // report failure, free temporary ownership, and leave the old flight usable.
    for (0..2) |allocation_index| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        var allocator = failing.allocator();
        var c: conn_mod.Connection = undefined;
        try prepare(&c, &allocator, .Client);
        defer c.deinit();
        var capture = LossCapture{};
        c.sender_ctx = &capture;
        c.sender_fn = LossCapture.send;
        const previous = c.crypto_retx_handshake.?;
        const offset = c.crypto_tx_off_handshake;
        const pn = c.pn_handshake_tx;
        failing.fail_index = failing.alloc_index + allocation_index;
        try testing.expectError(error.OutOfMemory, c.sendHandshakeCrypto(" suffix"));
        try testing.expect(failing.has_induced_failure);
        try testing.expectEqual(@as(usize, 0), capture.attempts);
        try testing.expect(previous.ptr == c.crypto_retx_handshake.?.ptr);
        try testing.expectEqualStrings("client Finished CRYPTO", c.crypto_retx_handshake.?);
        try testing.expectEqual(offset, c.crypto_tx_off_handshake);
        try testing.expectEqual(pn, c.pn_handshake_tx);
        try testing.expectEqual(@as(u64, 7), c.crypto_retx_handshake_off);
    }
}

fn expectConfirmedClientDiscards(installer: Installer) !void {
    var allocator = testing.allocator;
    var c: conn_mod.Connection = undefined;
    try prepare(&c, &allocator, .Client);
    defer c.deinit();
    c.handshake_done_seen = true;
    try install(&c, installer);
    try testing.expect(c.hs_tx_keys == null and c.hs_rx_keys == null);
    try testing.expect(c.crypto_retx_handshake == null);
    try testing.expect(!c.pto_handshake_active);
    try testing.expectEqual(@as(u64, 0), c.pto_handshake_id);
}

test "confirmed client discards Handshake keys and retained Finished via connection" {
    try expectConfirmedClientDiscards(.connection);
}

test "confirmed client discards Handshake keys and retained Finished via callback" {
    try expectConfirmedClientDiscards(.callback);
}

fn expectUnconfirmedServerRetains(installer: Installer) !void {
    var allocator = testing.allocator;
    var c: conn_mod.Connection = undefined;
    try prepare(&c, &allocator, .Server);
    defer c.deinit();
    c.peer_finished_verified = false;
    try install(&c, installer);
    try testing.expect(c.hs_tx_keys != null and c.hs_rx_keys != null);
    try testing.expect(c.crypto_retx_handshake != null);
    try testing.expect(c.pto_handshake_active);
}

test "server retains Handshake recovery before verifying client Finished via connection" {
    try expectUnconfirmedServerRetains(.connection);
}

test "server retains Handshake recovery before verifying client Finished via callback" {
    try expectUnconfirmedServerRetains(.callback);
}
