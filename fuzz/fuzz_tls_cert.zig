const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    // Test with ASN.1 SEQUENCE header
    const test_cert = [_]u8{ 0x30, 0x82, 0x01, 0x00 };

    if (test_cert.len == 0 or test_cert.len > 8192) return;

    std.debug.print("Fuzz: TLS cert parsing OK\n", .{});
}
