// MIT License
// tools/update_gap.zig — append summary to docs/GAP.md with timestamp
const std = @import("std");

fn writeStderr(bytes: []const u8) void {
    if (@import("builtin").target.os.tag == .windows) {
        const w = std.os.windows;
        const h = w.GetStdHandle(w.STD_ERROR_HANDLE) catch return;
        _ = std.posix.write(h, bytes) catch {};
    } else {
        _ = std.posix.write(std.posix.STDERR_FILENO, bytes) catch {};
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);
    if (args.len < 3 or !std.mem.eql(u8, args[1], "--summary")) {
        writeStderr("usage: update-gap --summary \"text\"\n");
        std.process.exit(2);
    }
    const summary = args[2];
    const path = "docs/GAP.md";
    var file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    defer file.close();
    try file.seekFromEnd(0);
    var buf: [256]u8 = undefined;
    const now = std.time.timestamp();
    const s = std.fmt.bufPrint(&buf, "\n\n### {d} — {s}\n", .{ now, summary }) catch return;
    _ = file.writeAll(s) catch {};
}
