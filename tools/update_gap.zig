// tools/update_gap.zig — append summary to docs/GAP.md with timestamp
const std = @import("std");

var tool_io: std.Io = undefined;

fn writeStderr(bytes: []const u8) void {
    std.Io.File.stderr().writeStreamingAll(tool_io, bytes) catch {};
}

pub fn main(init: std.process.Init) !void {
    tool_io = init.io;
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try init.minimal.args.toSlice(alloc);
    if (args.len < 3 or !std.mem.eql(u8, args[1], "--summary")) {
        writeStderr("usage: update-gap --summary \"text\"\n");
        std.process.exit(2);
    }
    const summary = args[2];
    const path = "docs/GAP.md";
    var file = try std.Io.Dir.cwd().openFile(tool_io, path, .{ .mode = .read_write });
    defer file.close(tool_io);
    const end_offset = (try file.stat(tool_io)).size;
    var buf: [256]u8 = undefined;
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.REALTIME, &ts);
    const s = std.fmt.bufPrint(&buf, "\n\n### {d} — {s}\n", .{ ts.sec, summary }) catch return;
    file.writePositionalAll(tool_io, s, end_offset) catch {};
}
