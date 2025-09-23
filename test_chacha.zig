const std = @import("std");

test "chacha20 basic" {
    const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;
    
    const key: [32]u8 = .{0} ** 32;
    const nonce: [12]u8 = .{0} ** 12;
    var block: [64]u8 = undefined;
    
    // Generate keystream
    ChaCha20IETF.xor(&block, &([_]u8{0} ** 64), 0, key, nonce);
    
    std.debug.print("ChaCha20 keystream (first 16 bytes): ", .{});
    for (block[0..16]) |b| {
        std.debug.print("{x:0>2} ", .{b});
    }
    std.debug.print("\n", .{});
    
    // Expected for all-zero key and nonce with counter=0
    // This should match the ChaCha20 test vectors
    const expected = [_]u8{
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
        0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
    };
    
    try std.testing.expectEqualSlices(u8, expected[0..16], block[0..16]);
}