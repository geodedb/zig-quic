const std = @import("std"); test "al" { const al = std.ArrayList(u8).initCapacity(std.testing.allocator, 0) catch unreachable; _ = &al; }
