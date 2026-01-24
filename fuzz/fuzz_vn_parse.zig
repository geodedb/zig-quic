const std = @import("std");
const pkt = @import("quic_packet");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    var out = std.ArrayList(u8){};
    defer out.deinit(alloc);
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
        _ = out.appendSlice(alloc, tmp[0..n]) catch break;
        if (out.items.len >= 4096) break;
    }
    const buf = out.items;
    const r = pkt.decodeVersionNegotiation(alloc, buf);
    if (r) |vn| {
        defer alloc.free(vn.versions);
        _ = pkt.shouldAcceptVersionNegotiation(pkt.QUIC_V1, vn.versions);
    } else |_| {}
}
