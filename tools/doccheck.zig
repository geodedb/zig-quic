// MIT License
// tools/doccheck.zig — ensure pub symbols in src/quic/* have doc comments.
const std = @import("std");

fn hasImmediateDoc(lines: []const []const u8, idx: usize) bool {
    var i = idx;
    while (i > 0) : (i -= 1) {
        const line = std.mem.trim(u8, lines[i - 1], " \t\r\n");
        if (line.len == 0) continue; // allow blank padding
        return std.mem.startsWith(u8, line, "///");
    }
    return false;
}

fn collectPaths(alloc: std.mem.Allocator, base: []const u8, out: *std.ArrayListUnmanaged([]const u8)) !void {
    var dir = try std.fs.cwd().openDir(base, .{ .iterate = true });
    defer dir.close();
    var it = dir.iterate();
    while (try it.next()) |e| {
        const child_path = try std.fs.path.join(alloc, &.{ base, e.name });
        switch (e.kind) {
            .file => {
                if (std.mem.endsWith(u8, child_path, ".zig")) {
                    try out.append(alloc, child_path);
                } else {
                    alloc.free(child_path);
                }
            },
            .directory => {
                try collectPaths(alloc, child_path, out);
                alloc.free(child_path);
            },
            else => alloc.free(child_path),
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var files = std.ArrayListUnmanaged([]const u8){};
    defer files.deinit(alloc);
    try collectPaths(alloc, "src/quic", &files);
    try collectPaths(alloc, "src/h3", &files);

    for (files.items) |path| {
        var file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        const contents = try file.readToEndAlloc(alloc, 1 << 20);
        defer alloc.free(contents);
        var lines_it = std.mem.tokenizeScalar(u8, contents, '\n');
        var lines = std.ArrayListUnmanaged([]const u8){};
        defer lines.deinit(alloc);
        while (lines_it.next()) |line| try lines.append(alloc, line);
        const arr = lines.items;
        for (arr, 0..) |line, idx| {
            const t = std.mem.trim(u8, line, " \t\r");
            if (std.mem.startsWith(u8, t, "pub const") or std.mem.startsWith(u8, t, "pub fn") or std.mem.startsWith(u8, t, "pub struct") or std.mem.startsWith(u8, t, "pub var")) {
                if (!hasImmediateDoc(arr, idx)) {
                    std.debug.print("doccheck: missing doc comment in {s}:{d}\n", .{ path, idx + 1 });
                    std.process.exit(1);
                }
            }
        }
        alloc.free(path);
    }
}
