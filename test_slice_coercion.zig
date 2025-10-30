const std = @import("std");

fn takesSlice(data: []const u8) void {
    std.debug.print("Received slice with length={}, first byte={X:0>2}\n", .{data.len, data[0]});
}

pub fn main() !void {
    var arr: [16]u8 = .{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0} ++ .{0} ** 8;
    
    std.debug.print("Test 1: Pass &arr\n", .{});
    takesSlice(&arr);
    
    std.debug.print("\nTest 2: Pass arr[0..]\n", .{});
    takesSlice(arr[0..]);
}
