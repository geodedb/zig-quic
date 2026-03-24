const std = @import("std");
const ks = @import("quic_tls");

pub fn deriveStatelessResetToken(base: *const [32]u8, sequence: u64, cid_bytes: []const u8) error{InvalidCidLength}![16]u8 {
    var ikm_buf: [8 + 20]u8 = undefined;
    var seq_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_be, sequence, .big);
    @memcpy(ikm_buf[0..8], &seq_be);
    const cid_len = cid_bytes.len;
    if (cid_len > 20) return error.InvalidCidLength;
    @memcpy(ikm_buf[8 .. 8 + cid_len], cid_bytes);
    const prk = ks.extract(base, ikm_buf[0 .. 8 + cid_len]);
    var out: [16]u8 = undefined;
    ks.expandLabel(prk, "reset token", &[_]u8{}, out[0..]) catch unreachable;
    return out;
}

pub fn testDeriveStatelessResetToken(base: *const [32]u8, sequence: u64, cid: []const u8) error{InvalidCidLength}![16]u8 {
    return deriveStatelessResetToken(base, sequence, cid);
}
