const std = @import("std");

fn rp(s: []const u8) std.Build.LazyPath {
    if (@hasField(std.Build.LazyPath, "path")) {
        return .{ .path = s };
    } else {
        return .{ .cwd_relative = s };
    }
}

fn mkModule(b: *std.Build, path: []const u8) *std.Build.Module {
    if (@hasDecl(std.Build, "createModule")) {
        return b.createModule(.{ .root_source_file = rp(path) });
    } else {
        return b.createModule(.{ .root_source_file = rp(path) });
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // CLI tool: quic-varint
    const varint_exe = b.addExecutable(.{
        .name = "quic-varint",
        .root_source_file = rp("tools/varint_tool.zig"),
        .target = target,
        .optimize = optimize,
    });
    const install_varint = b.addInstallArtifact(varint_exe, .{});

    // tools: update-gap, doccheck
    const update_gap = b.addExecutable(.{
        .name = "update-gap",
        .root_source_file = rp("tools/update_gap.zig"),
        .target = target,
        .optimize = optimize,
    });
    const install_update_gap = b.addInstallArtifact(update_gap, .{});

    const doccheck = b.addExecutable(.{
        .name = "doccheck",
        .root_source_file = rp("tools/doccheck.zig"),
        .target = target,
        .optimize = optimize,
    });
    const install_doccheck = b.addInstallArtifact(doccheck, .{});

    const tools_step = b.step("tools", "Build CLI tools");
    tools_step.dependOn(&install_varint.step);
    tools_step.dependOn(&install_update_gap.step);
    tools_step.dependOn(&install_doccheck.step);

    const step_doccheck = b.step("doccheck", "Run documentation checker");
    step_doccheck.dependOn(&install_doccheck.step);

    const step_update_gap = b.step("update-gap", "Install update-gap tool");
    step_update_gap.dependOn(&install_update_gap.step);

    // Tests
    const test_step = b.step("test", "Run unit tests");
    const test_filter = b.option([]const u8, "test-filter", "Filter tests by substring");

    const only_tls_kat = blk: {
        if (test_filter) |f| break :blk std.mem.eql(u8, f, "tls_key_schedule_kat") else break :blk false;
    };

    if (!only_tls_kat) {
        const test_quic = b.addTest(.{ .root_source_file = rp("quic.zig"), .target = target, .optimize = optimize });
        const run_test_quic = b.addRunArtifact(test_quic);
        test_step.dependOn(&run_test_quic.step);
    }

    // Expose TLS key schedule as a module for tests
    const quic_tls_mod = mkModule(b, "src/quic/tls/key_schedule.zig");

    const test_tls = b.addTest(.{ .root_source_file = rp("tests/test_tls_key_schedule.zig"), .target = target, .optimize = optimize });
    test_tls.root_module.addImport("quic_tls", quic_tls_mod);

    const run_test_tls = b.addRunArtifact(test_tls);
    test_step.dependOn(&run_test_tls.step);

    // Fuzzers: build executables
    const fuzz_varint = b.addExecutable(.{ .name = "fuzz_varint", .root_source_file = rp("fuzz/fuzz_varint.zig"), .target = target, .optimize = optimize });
    const fuzz_frame = b.addExecutable(.{ .name = "fuzz_frame_parse", .root_source_file = rp("fuzz/fuzz_frame_parse.zig"), .target = target, .optimize = optimize });
    const install_fuzz_varint = b.addInstallArtifact(fuzz_varint, .{});
    const install_fuzz_frame = b.addInstallArtifact(fuzz_frame, .{});
    const fuzz_step = b.step("fuzz", "Build fuzzers");
    fuzz_step.dependOn(&install_fuzz_varint.step);
    fuzz_step.dependOn(&install_fuzz_frame.step);

    // Benchmarks
    const bench = b.addExecutable(.{ .name = "quic-bench", .root_source_file = rp("bench/main.zig"), .target = target, .optimize = optimize });
    const install_bench = b.addInstallArtifact(bench, .{});
    const bench_step = b.step("bench", "Build benchmarks");
    bench_step.dependOn(&install_bench.step);
}
