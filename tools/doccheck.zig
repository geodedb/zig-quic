// MIT License
// tools/doccheck.zig — ensure pub symbols in src/quic/* have doc comments.
const std = @import("std");

fn hasDocComment(lines: []const []const u8, idx: usize) bool {
    if (idx == 0) return false;
    var i = idx;
    while (i > 0) : (i -= 1) {
        const line = std.mem.trim(u8, lines[i - 1], " \t\r\n");
        if (line.len == 0) continue; // skip blanks
        return std.mem.startsWith(u8, line, "///");
    }
    return false;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    var it = try std.fs.cwd().openIterableDir("src/quic", .{ .recursor = true });
    defer it.close();
    var failed: bool = false;
    var walker = it.walk();
    while (try walker.next()) |e| {
        if (e.kind != .file) continue;
        if (!std.mem.endsWith(u8, e.path, ".zig")) continue;
        var file = try e.dir.openFile(e.path, .{});
        defer file.close();
        const contents = try file.readToEndAlloc(alloc, 1 << 20);
        defer alloc.free(contents);
        var lines_it = std.mem.tokenizeScalar(u8, contents, '\n');
        var lines = std.ArrayList([]const u8).init(alloc);
        defer lines.deinit();
        while (lines_it.next()) |line| try lines.append(line);
        const arr = lines.items;
        for (arr, 0..) |line, idx| {
            const t = std.mem.trim(u8, line, " \t\r");
            if (std.mem.startsWith(u8, t, "pub ")) {
                if (!hasDocComment(arr, idx)) {
                    std.debug.print("doccheck: missing doc comment in {s}:{d}\n", .{ e.path, idx + 1 });
                    failed = true;
                }
            }
        }
    }
    if (failed) std.process.exit(1);
}
