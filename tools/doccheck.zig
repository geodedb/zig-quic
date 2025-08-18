// MIT License
// tools/doccheck.zig — basic checker to ensure pub symbols in src/quic/* have doc comments.
// This is a stub: currently always succeeds but prints a note.
const std = @import("std");

pub fn main() !void {
    _ = std.io.getStdOut().writer().write("doccheck: stub pass\n") catch {};
}
