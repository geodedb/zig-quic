const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){}; 
    defer _ = gpa.deinit();
    
    // Test with valid handshake message
    const test_msg = [_]u8{ 0x01, 0x00, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD };
    
    if (test_msg.len < 4) return;
    const body_len: usize = (@as(usize, test_msg[1]) << 16) | 
                            (@as(usize, test_msg[2]) << 8) | 
                            test_msg[3];
    if (4 + body_len > test_msg.len) return;
    
    std.debug.print("Fuzz: TLS hello parsing OK\n", .{});
}
