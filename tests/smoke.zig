const std = @import("std");

// Grouped smoke entrypoint to keep the default test graph compact.
test "grouped smoke suite imports" {
    _ = @import("test_public_quic_exports.zig");
    _ = @import("test_byteorder.zig");
    _ = @import("test_transport_geode_compat.zig");
    _ = @import("unit/version/test_version.zig");
    _ = @import("integration/ci_helpers.zig");
}

test "grouped smoke sanity" {
    try std.testing.expect(true);
}
