const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // CLI tool: quic-varint
    const varint_exe = b.addExecutable(.{
        .name = "quic-varint",
        .root_source_file = .{ .path = "tools/varint_tool.zig" },
        .target = target,
        .optimize = optimize,
    });
    const install_varint = b.addInstallArtifact(varint_exe, .{});

    const tools_step = b.step("tools", "Build CLI tools");
    tools_step.dependOn(&install_varint.step);

    const test_step = b.step("test", "Run unit tests");

    // Allow passing `zig build test --test-filter <substr>`
    const test_filter = b.option([]const u8, "test-filter", "Filter tests by substring");

    const only_tls_kat = blk: {
        if (test_filter) |f| {
            break :blk std.mem.eql(u8, f, "tls_key_schedule_kat");
        } else break :blk false;
    };

    if (!only_tls_kat) {
        const test_quic = b.addTest(.{
            .root_source_file = .{ .path = "quic.zig" },
            .target = target,
            .optimize = optimize,
        });
        const run_test_quic = b.addRunArtifact(test_quic);
        if (test_filter) |f| {
            run_test_quic.addArg("--test-filter");
            run_test_quic.addArg(f);
        }
        test_step.dependOn(&run_test_quic.step);
    }

    const test_tls = b.addTest(.{
        .root_source_file = .{ .path = "tests/test_tls_key_schedule.zig" },
        .target = target,
        .optimize = optimize,
    });
    const run_test_tls = b.addRunArtifact(test_tls);
    if (test_filter) |f| {
        run_test_tls.addArg("--test-filter");
        run_test_tls.addArg(f);
    }
    test_step.dependOn(&run_test_tls.step);
}
