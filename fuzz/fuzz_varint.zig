const std = @import("std");
const varint = @import("quic_varint");

pub fn main() !void {
    // Simple standalone fuzzer harness compatible with libFuzzer-like runners.
    // Reads stdin to a buffer and attempts varint decode.
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
    _ = varint.decode(buf) catch {};
}
