// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Helpers for the key update tests that inject 1-RTT packets into a real
// client endpoint's receive path (Endpoint.testInject) with keys seeded on
// its connection (SONNY-6656).

const std = @import("std");
const linux = std.os.linux;
const ks = @import("quic_tls");
const key_update = @import("quic_key_update");
const packet = @import("quic_packet");

pub fn nowNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub fn seedSecret(byte_seed: u8) ks.Secret {
    var s = ks.Secret.empty();
    s.len = @intCast(ks.digestLength(.sha256));
    for (s.sliceMut(), 0..) |*b, i| b.* = @as(u8, @intCast((i + @as(usize, byte_seed)) & 0xff));
    return s;
}

/// The peer's 1-RTT keys of the first two generations. The header
/// protection key does not change with a key update (RFC 9001 §6).
pub const PeerKeys = struct { gen0: packet.AeadKeys, gen1: packet.AeadKeys };

/// Gives connection `c` the receive keys of generation 0 (and the next
/// generation pre-derived, as installApplicationKeys does), send keys, and
/// a confirmed handshake. Returns the keys the peer sends with.
pub fn seedKeys(c: anytype) !PeerKeys {
    const rx0 = seedSecret(7);
    const m0 = ks.deriveKeyIvHpHash(.sha256, &rx0, c.version_v2);
    const rx1 = try key_update.deriveNextTrafficSecret(.sha256, &rx0);
    const m1 = ks.deriveKeyIvHpHash(.sha256, &rx1, c.version_v2);
    const tx0 = seedSecret(9);
    const mt = ks.deriveKeyIvHpHash(.sha256, &tx0, c.version_v2);
    const gen0 = packet.AeadKeys{ .key = m0.key, .iv = m0.iv, .hp = m0.hp };
    const gen1 = packet.AeadKeys{ .key = m1.key, .iv = m1.iv, .hp = m0.hp };
    c.app_rx_secret = rx0;
    c.app_rx_keys = gen0;
    c.app_rx_next_secret = rx1;
    c.app_rx_next_keys = gen1;
    c.app_tx_secret = tx0;
    c.app_tx_keys = .{ .key = mt.key, .iv = mt.iv, .hp = mt.hp };
    c.rx_key_phase = false;
    c.tx_key_phase = false;
    c.peer_finished_verified = true;
    c.handshake_done_seen = true;
    c.disable_auto_key_update = true;
    return .{ .gen0 = gen0, .gen1 = gen1 };
}

/// A PING padded to 20 bytes: ack-eliciting, and long enough for a header
/// protection sample.
pub const ping_payload = [_]u8{0x01} ++ [_]u8{0x00} ** 19;

/// Sends the client a 1-RTT packet numbered `pn` with `keys` and `phase`.
pub fn inject(alloc: std.mem.Allocator, ep: anytype, c: anytype, pn: u64, keys: packet.AeadKeys, phase: bool) !void {
    const dcid = c.our_scid.bytes[0..c.our_scid.len];
    const p = try packet.encodeShortProtected(alloc, dcid, pn, 2, &ping_payload, keys, phase);
    defer alloc.free(p);
    ep.testInject(c.peer, p);
}

/// Whether packet `pn` (below 256) was received.
pub fn received(c: anytype, pn: u64) bool {
    return c.pn_app.have_any and pn <= c.pn_app.max and c.pn_app.win.isSet(@intCast(pn));
}
