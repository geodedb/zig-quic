// MIT License
// tools/update_gap.zig — append summary to docs/GAP.md with timestamp
const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);
    if (args.len < 3 or !std.mem.eql(u8, args[1], "--summary")) {
        try std.io.getStdErr().writer().writeAll("usage: update-gap --summary \"text\"\n");
        std.process.exit(2);
    }
    const summary = args[2];
    const path = "docs/GAP.md";
    var file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    defer file.close();
    try file.seekFromEnd(0);
    var w = file.writer();
    const now = std.time.timestamp();
    try w.print("\n\n### {d} — {s}\n", .{ now, summary });
}
