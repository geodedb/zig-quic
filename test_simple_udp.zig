const std = @import("std");
const posix = std.posix;

pub fn main() !void {
    // Create server socket
    const server_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    defer posix.close(server_fd);

    // Set SO_REUSEADDR
    var one: i32 = 1;
    _ = posix.setsockopt(server_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};

    // Bind to port 4444
    var server_addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 4444),
        .addr = std.mem.nativeToBig(u32, 0x7f000001), // 127.0.0.1
        .zero = [_]u8{0} ** 8,
    };
    const server_sa: *const posix.sockaddr = @ptrCast(&server_addr);
    try posix.bind(server_fd, server_sa, @sizeOf(posix.sockaddr.in));

    std.debug.print("Server bound to 127.0.0.1:4444\n", .{});

    // Create client socket
    const client_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    defer posix.close(client_fd);

    // Send message from client to server
    const msg = "Hello UDP";
    const sent = try posix.sendto(client_fd, msg, 0, server_sa, @sizeOf(posix.sockaddr.in));
    std.debug.print("Client sent {} bytes\n", .{sent});

    // Server receives
    var buf: [1024]u8 = undefined;
    var peer_addr: posix.sockaddr.storage = undefined;
    var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    const recv_len = try posix.recvfrom(server_fd, buf[0..], 0, @ptrCast(&peer_addr), &peer_len);

    std.debug.print("Server received: {s}\n", .{buf[0..recv_len]});
}