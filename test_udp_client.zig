const std = @import("std");

pub fn main() !void {
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);

    const server_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 4433);

    // Send a simple UDP packet
    const data = "Test UDP packet";
    const sent = try std.posix.sendto(sock, data, 0, &server_addr.any, server_addr.getOsSockLen());

    std.debug.print("Sent {} bytes to 127.0.0.1:4433\n", .{sent});
}