const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    // Test 1: Try using init
    var list1 = std.ArrayList(*anyopaque).init(alloc);
    defer list1.deinit();

    std.debug.print("Success!\n", .{});
}
