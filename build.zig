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
    // Also provide a run step to append to GAP.md when a -Dgap-summary option is passed.
    const gap_summary = b.option([]const u8, "gap-summary", "Summary string to append to GAP.md");
    if (gap_summary) |summary| {
        const run_update = b.addRunArtifact(update_gap);
        run_update.addArg("--summary");
        run_update.addArg(summary);
        step_update_gap.dependOn(&run_update.step);
    }

    // Tests
    const test_step = b.step("test", "Run unit tests");
    const test_filter = b.option([]const u8, "test-filter", "Filter tests by substring");
    const legacy_tests = b.option(bool, "legacy-tests", "Run legacy tests in quic.zig") orelse false;

    // Expose TLS/crypto/packet modules
    const quic_tls_mod = mkModule(b, "src/quic/tls/key_schedule.zig");
    const quic_crypto_mod = mkModule(b, "src/quic/crypto_quic.zig");
    const quic_packet_mod = mkModule(b, "src/quic/packet.zig");
    quic_packet_mod.addImport("quic_tls", quic_tls_mod);
    quic_packet_mod.addImport("quic_crypto", quic_crypto_mod);

    // New TLS modules available to tests
    const tls13_mod = mkModule(b, "src/quic/tls/tls13.zig");
    // Allow '@import("key_schedule.zig")' inside tls13 to resolve via local path
    tls13_mod.addImport("quic_tls", quic_tls_mod);
    const asn1_mod = mkModule(b, "src/quic/tls/asn1.zig");
    const x509_mod = mkModule(b, "src/quic/tls/x509.zig");
    _ = asn1_mod;
    _ = x509_mod;

    // Provide varint module for frame decoding to avoid duplicate include
    const quic_varint_mod = mkModule(b, "src/quic/varint.zig");
    const quic_frame_mod = mkModule(b, "src/quic/frame.zig");
    quic_frame_mod.addImport("quic_varint", quic_varint_mod);
    quic_packet_mod.addImport("quic_varint", quic_varint_mod);

    // Special-case: if filtering for the TLS KAT, only run that test file.
    if (test_filter) |f| {
        if (std.mem.containsAtLeast(u8, f, 1, "tls_key_schedule_kat")) {
            const test_tls_only = b.addTest(.{ .root_source_file = rp("tests/test_tls_key_schedule.zig"), .target = target, .optimize = optimize });
            test_tls_only.root_module.addImport("quic_tls", quic_tls_mod);
            const run_test_tls_only = b.addRunArtifact(test_tls_only);
            test_step.dependOn(&run_test_tls_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "timers")) {
            const quic_api_mod = mkModule(b, "src/quic/api.zig");
            quic_api_mod.addImport("quic_crypto", quic_crypto_mod);
            quic_api_mod.addImport("quic_frame", quic_frame_mod);
            quic_api_mod.addImport("quic_varint", quic_varint_mod);
            quic_api_mod.addImport("tls/key_schedule.zig", quic_tls_mod);
            quic_api_mod.addImport("quic_tls", quic_tls_mod);
            const test_timers_only = b.addTest(.{ .root_source_file = rp("tests/test_timers.zig"), .target = target, .optimize = optimize });
            test_timers_only.root_module.addImport("quic_api", quic_api_mod);
            const run_test_timers_only = b.addRunArtifact(test_timers_only);
            test_step.dependOn(&run_test_timers_only.step);
            return;
        }
    }

    if (!legacy_tests) {
        // Regular test suite
        const test_tls = b.addTest(.{ .root_source_file = rp("tests/test_tls_key_schedule.zig"), .target = target, .optimize = optimize });
        test_tls.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_tls = b.addRunArtifact(test_tls);
        test_step.dependOn(&run_test_tls.step);

        // Handshake secrets transition test
        const test_tls_hs = b.addTest(.{ .root_source_file = rp("tests/test_tls_handshake_secrets.zig"), .target = target, .optimize = optimize });
        test_tls_hs.root_module.addImport("quic_tls13", tls13_mod);
        test_tls_hs.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_tls_hs = b.addRunArtifact(test_tls_hs);
        test_step.dependOn(&run_test_tls_hs.step);

        // Initial protection roundtrip test
        const test_initial = b.addTest(.{ .root_source_file = rp("tests/test_initial_protect.zig"), .target = target, .optimize = optimize });
        test_initial.root_module.addImport("quic_tls", quic_tls_mod);
        test_initial.root_module.addImport("quic_crypto", quic_crypto_mod);
        const run_test_initial = b.addRunArtifact(test_initial);
        test_step.dependOn(&run_test_initial.step);

        // RFC 9001 Appendix A Initial byte-exact test
        const test_rfc_a1 = b.addTest(.{ .root_source_file = rp("tests/test_rfc9001_a1_initial.zig"), .target = target, .optimize = optimize });
        test_rfc_a1.root_module.addImport("quic_tls", quic_tls_mod);
        test_rfc_a1.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_rfc_a1.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_rfc_a1 = b.addRunArtifact(test_rfc_a1);
        test_step.dependOn(&run_test_rfc_a1.step);

        // RFC 9001 Appendix A.3 Server Initial byte-exact test
        const test_rfc_a3 = b.addTest(.{ .root_source_file = rp("tests/test_rfc9001_a3_server_initial.zig"), .target = target, .optimize = optimize });
        test_rfc_a3.root_module.addImport("quic_tls", quic_tls_mod);
        test_rfc_a3.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_rfc_a3.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_rfc_a3 = b.addRunArtifact(test_rfc_a3);
        test_step.dependOn(&run_test_rfc_a3.step);

        // CRYPTO extraction from Initial payload
        const test_crypto_extract = b.addTest(.{ .root_source_file = rp("tests/test_crypto_extract.zig"), .target = target, .optimize = optimize });
        test_crypto_extract.root_module.addImport("quic_tls", quic_tls_mod);
        test_crypto_extract.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_crypto_extract.root_module.addImport("quic_packet", quic_packet_mod);
        test_crypto_extract.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_crypto_extract = b.addRunArtifact(test_crypto_extract);
        test_step.dependOn(&run_test_crypto_extract.step);

        // New end-to-end Initial->Handshake loop test
        const test_loop = b.addTest(.{ .root_source_file = rp("tests/test_initial_handshake_loop.zig"), .target = target, .optimize = optimize });
        test_loop.root_module.addImport("quic_tls", quic_tls_mod);
        test_loop.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_loop.root_module.addImport("quic_packet", quic_packet_mod);
        test_loop.root_module.addImport("quic_frame", quic_frame_mod);
        test_loop.root_module.addImport("quic_tls13", tls13_mod);
        test_loop.root_module.addImport("quic_varint", quic_varint_mod);
        const run_test_loop = b.addRunArtifact(test_loop);
        test_step.dependOn(&run_test_loop.step);

        // Timer tests (now enabled by default)
        const quic_api_mod = mkModule(b, "src/quic/api.zig");
        quic_api_mod.addImport("quic_crypto", quic_crypto_mod);
        quic_api_mod.addImport("quic_frame", quic_frame_mod);
        quic_api_mod.addImport("quic_varint", quic_varint_mod);
        quic_api_mod.addImport("tls/key_schedule.zig", quic_tls_mod);
        quic_api_mod.addImport("quic_tls", quic_tls_mod);
        const test_timers = b.addTest(.{ .root_source_file = rp("tests/test_timers.zig"), .target = target, .optimize = optimize });
        test_timers.root_module.addImport("quic_api", quic_api_mod);
        const run_test_timers = b.addRunArtifact(test_timers);
        test_step.dependOn(&run_test_timers.step);
    } else {
        // Optional legacy tests
        const test_quic = b.addTest(.{ .root_source_file = rp("quic.zig"), .target = target, .optimize = optimize });
        const run_test_quic = b.addRunArtifact(test_quic);
        test_step.dependOn(&run_test_quic.step);
    }

    // Fuzzers: build executables
    const fuzz_varint = b.addExecutable(.{ .name = "fuzz_varint", .root_source_file = rp("fuzz/fuzz_varint.zig"), .target = target, .optimize = optimize });
    const fuzz_frame = b.addExecutable(.{ .name = "fuzz_frame_parse", .root_source_file = rp("fuzz/fuzz_frame_parse.zig"), .target = target, .optimize = optimize });

    // Provide modules to fuzzers
    fuzz_varint.root_module.addImport("quic_varint", quic_varint_mod);
    fuzz_frame.root_module.addImport("quic_frame", quic_frame_mod);
    fuzz_frame.root_module.addImport("quic_varint", quic_varint_mod);

    const install_fuzz_varint = b.addInstallArtifact(fuzz_varint, .{});
    const install_fuzz_frame = b.addInstallArtifact(fuzz_frame, .{});
    const fuzz_step = b.step("fuzz", "Build fuzzers");
    fuzz_step.dependOn(&install_fuzz_varint.step);
    fuzz_step.dependOn(&install_fuzz_frame.step);

    // Benchmarks
    const bench = b.addExecutable(.{ .name = "quic-bench", .root_source_file = rp("bench/main.zig"), .target = target, .optimize = optimize });
    // Provide varint module to benchmark
    bench.root_module.addImport("quic_varint", quic_varint_mod);
    const install_bench = b.addInstallArtifact(bench, .{});
    const bench_step = b.step("bench", "Build benchmarks");
    bench_step.dependOn(&install_bench.step);
}
