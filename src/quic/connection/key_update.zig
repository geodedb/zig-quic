const ks = @import("quic_tls");

/// Derive the next QUIC application traffic secret for RFC 9001 key update.
///
/// The upstream TLS package removed its `updateQuicSecretHash` helper, so QUIC
/// callers derive the next secret directly with HKDF-Expand-Label using the
/// RFC 9001 Section 6 label "quic ku". Keep this fallible so crypto call sites
/// cannot hide impossible-looking key schedule errors behind `unreachable`.
pub fn deriveNextTrafficSecret(hash: ks.Hash, current_secret: *const ks.Secret) !ks.Secret {
    var next = ks.Secret.empty();
    next.len = @intCast(ks.digestLength(hash));
    try ks.expandLabelHash(hash, current_secret, "quic ku", &[_]u8{}, next.sliceMut());
    return next;
}

test "RFC 9001 Section 6 key update derivation is deterministic and fallible" {
    const std = @import("std");

    var current = ks.Secret.empty();
    current.len = @intCast(ks.digestLength(.sha256));
    for (current.sliceMut(), 0..) |*b, i| b.* = @intCast(i);

    const first = try deriveNextTrafficSecret(.sha256, &current);
    const second = try deriveNextTrafficSecret(.sha256, &current);

    try std.testing.expectEqualSlices(u8, first.slice(), second.slice());
    try std.testing.expect(!std.mem.eql(u8, current.slice(), first.slice()));
}
