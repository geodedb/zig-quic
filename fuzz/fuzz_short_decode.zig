const std = @import("std");
const pkt = @import("quic_packet");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();
    const buf = try std.io.getStdIn().readToEndAlloc(a, 4096);
    defer a.free(buf);
    if (buf.len < 5) return; // need first + dcid + pn
    // Try a few dcid lengths 0..4 derived from input
    const dcid_len: usize = @intCast(buf[0] & 0x03);
    if (1 + dcid_len + 1 >= buf.len) return;
    const dcid = buf[1 .. 1 + dcid_len];
    const keys = pkt.AeadKeys{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    _ = pkt.decodeShortProtected(a, buf, dcid.len, keys) catch {};
}
