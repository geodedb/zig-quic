// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Connection ID management and stateless reset token handling.
//!
//! RFC 9000 §5.1: Connection ID
//! RFC 9000 §5.2: Matching Packets to Connections
//! RFC 9000 §5.3: Connection ID Management
//! RFC 9000 §10.3: Stateless Reset

const std = @import("std");
const types = @import("types");
const ks = @import("quic_tls");

/// Local connection ID with sequence number and stateless reset token.
/// RFC 9000 §5.3: Each endpoint maintains a set of CIDs it advertises to its peer.
pub const LocalCid = struct {
    in_use: bool = false,
    sequence: u64 = 0,
    cid: types.Cid = .{},
    reset_token: [16]u8 = [_]u8{0} ** 16,
};

/// Derive stateless reset token using HKDF.
/// RFC 9000 §10.3: Endpoints must be able to generate stateless reset tokens
/// that are computationally difficult to guess.
///
/// Uses HKDF-Extract with base as salt and (sequence || cid) as IKM,
/// then HKDF-Expand-Label to derive the final 16-byte token.
pub fn deriveStatelessResetToken(base: *const [32]u8, sequence: u64, cid_bytes: []const u8) [16]u8 {
    // HKDF based derivation (implementation choice following RFC 9000 §10.3 guidance).
    // prk = HKDF-Extract(salt = base, ikm = sequence||cid)
    var ikm_buf: [8 + 20]u8 = undefined; // CID <= 20 bytes in this implementation
    var seq_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_be, sequence, .big);
    @memcpy(ikm_buf[0..8], &seq_be);
    const cid_len = cid_bytes.len;
    if (cid_len > 20) unreachable; // defensive (our Cid max 20)
    @memcpy(ikm_buf[8 .. 8 + cid_len], cid_bytes);
    const prk = ks.extract(base, ikm_buf[0 .. 8 + cid_len]);
    var out: [16]u8 = undefined;
    // token = HKDF-Expand-Label(prk, "reset token", "", 16)
    const empty_slice: []const u8 = &.{};
    ks.expandLabel(&prk, "reset token", empty_slice, out[0..]) catch unreachable;
    return out;
}

/// Test helper exposing reset token derivation (used only by unit tests).
pub fn testDeriveStatelessResetToken(base: *const [32]u8, sequence: u64, cid: []const u8) [16]u8 {
    return deriveStatelessResetToken(base, sequence, cid);
}
