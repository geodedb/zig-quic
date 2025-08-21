const std = @import("std");
const pkt = @import("quic_packet");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    const buf = try std.io.getStdIn().readToEndAlloc(alloc, 4096);
    defer alloc.free(buf);
    const r = pkt.decodeVersionNegotiation(alloc, buf);
    if (r) |vn| {
        // basic sanity on versions list; free allocation
        defer alloc.free(vn.versions);
        // ensure downgrade helper runs
        _ = pkt.shouldAcceptVersionNegotiation(pkt.QUIC_V1, vn.versions);
    } else |_| {}
}
