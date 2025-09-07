const std = @import("std");
const pkt = @import("quic_packet");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();
    var out = std.ArrayList(u8){};
    defer out.deinit(a);
    var tmp: [4096]u8 = undefined;
    var infd: std.posix.fd_t = undefined;
    if (@import("builtin").target.os.tag == .windows) {
        const w = std.os.windows;
        infd = w.GetStdHandle(w.STD_INPUT_HANDLE) catch unreachable;
    } else {
        infd = std.posix.STDIN_FILENO;
    }
    while (true) {
        const n = std.posix.read(infd, tmp[0..]) catch break;
        if (n == 0) break;
        _ = out.appendSlice(a, tmp[0..n]) catch break;
        if (out.items.len >= 4096) break;
    }
    const buf = out.items;
    if (buf.len < 5) return; // need first + dcid + pn
    // Try a few dcid lengths 0..4 derived from input
    const dcid_len: usize = @intCast(buf[0] & 0x03);
    if (1 + dcid_len + 1 >= buf.len) return;
    const dcid = buf[1 .. 1 + dcid_len];
    const keys = pkt.AeadKeys{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    _ = pkt.decodeShortProtected(a, buf, dcid.len, keys) catch {};
}
