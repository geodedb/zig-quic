const std = @import("std");
const frame = @import("quic_frame");
const varint = @import("quic_varint");

// Minimal parser for the subset we write (padding/ping/stream)
fn parseFrame(data: []const u8) void {
    if (data.len == 0) return;
    const t = data[0];
    switch (t) {
        0x00, 0x01 => return, // padding/ping
        0x08...0x0f => {
            const off: usize = 1;
            _ = varint.decode(data[off..]) catch return; // stream_id
        },
        else => return,
    }
}

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
    parseFrame(buf);
}
