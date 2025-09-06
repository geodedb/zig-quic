const std = @import("std");
const conn_mod = @import("../src/quic/conn.zig");

// Deterministic test for HKDF-based stateless reset token derivation.
// We fix a base secret, sequence, and CID and assert expected 16 bytes.
// If the derivation algorithm changes, this test will fail requiring an
// explicit vector update (acts as a guard against accidental regression).

fn hex(bytes: []const u8) []const u8 {
    return std.fmt.bytesToHex(bytes, .lower);
}

pub fn main() !void {}

test "stateless_reset_token_hkdf_vector" {
    var base: [32]u8 = undefined;
    // Arbitrary fixed base pattern (not secret) for test vector.
    // 0x00..0x1f
    var i: usize = 0;
    while (i < base.len) : (i += 1) {
        base[i] = @intCast(i);
    }

    const sequence: u64 = 0x0102030405060708; // big-endian encoded inside derivation
    const cid = [_]u8{ 0xA1, 0xB2, 0xC3, 0xD4, 0x05, 0x06, 0x07, 0x08 };

    const token = conn_mod.testDeriveStatelessResetToken(&base, sequence, &cid);

    const expected = [_]u8{
        // Pre-computed via same function (locked in as vector):
        0x3a, 0x39, 0x2f, 0x14, 0x55, 0x2c, 0x58, 0x62,
        0x6a, 0x94, 0xbc, 0x0f, 0x6a, 0x5b, 0x79, 0x2e,
    };

    try std.testing.expectEqualSlices(u8, &expected, &token);

    // Spot-check invariance: re-derive with same inputs.
    const token2 = conn_mod.testDeriveStatelessResetToken(&base, sequence, &cid);
    try std.testing.expect(std.mem.eql(u8, &token, &token2));

    // Changing sequence should change token.
    const token_seq_delta = conn_mod.testDeriveStatelessResetToken(&base, sequence + 1, &cid);
    try std.testing.expect(!std.mem.eql(u8, &token, &token_seq_delta));

    // Changing CID should change token.
    const cid2 = [_]u8{ 0xA1, 0xB2, 0xC3, 0xD4, 0x05, 0x06, 0x07, 0x09 };
    const token_cid_delta = conn_mod.testDeriveStatelessResetToken(&base, sequence, &cid2);
    try std.testing.expect(!std.mem.eql(u8, &token, &token_cid_delta));

    // Print (optional) for debugging when updating vectors.
    std.log.debug("stateless reset token = {s}", .{hex(&token)});
}
