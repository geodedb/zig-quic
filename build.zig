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
    const optimize_base = b.standardOptimizeOption(.{});
    const release_safe = b.option(bool, "release-safe", "Build with ReleaseSafe optimization (convenience flag)") orelse false;
    const optimize: std.builtin.OptimizeMode = if (release_safe) .ReleaseSafe else optimize_base;

    // Parse optional user args to support `zig build test --test-filter <substr>`.
    const raw_args = b.args orelse &[_][]const u8{};
    var user_filter: ?[]const u8 = null;
    var i: usize = 0;
    while (i < raw_args.len) : (i += 1) {
        if (std.mem.eql(u8, raw_args[i], "--test-filter")) {
            if (i + 1 < raw_args.len) user_filter = raw_args[i + 1];
            break;
        }
    }

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

    // Add interop runner tool
    const interop_runner = b.addExecutable(.{
        .name = "interop-runner",
        .root_source_file = rp("tools/interop_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    const install_interop = b.addInstallArtifact(interop_runner, .{});
    tools_step.dependOn(&install_interop.step);

    const interop_list = b.step("interop-list", "List interop scenarios");
    interop_list.dependOn(&install_interop.step);
    const interop_run = b.step("interop-run", "Run interop scenario via -Dscenario=...");
    interop_run.dependOn(&install_interop.step);
    const scenario = b.option([]const u8, "scenario", "Interop scenario to run");
    if (scenario) |sc| {
        const run = b.addRunArtifact(interop_runner);
        run.addArg("run");
        run.addArg(sc);
        interop_run.dependOn(&run.step);
    } else {
        const run = b.addRunArtifact(interop_runner);
        run.addArg("list");
        interop_list.dependOn(&run.step);
    }

    const step_doccheck = b.step("doccheck", "Run documentation checker");
    step_doccheck.dependOn(&install_doccheck.step);

    const step_update_gap = b.step("update-gap", "Install update-gap tool");
    step_update_gap.dependOn(&install_update_gap.step);
    const gap_summary = b.option([]const u8, "gap-summary", "Summary string to append to GAP.md");
    if (gap_summary) |summary| {
        const run_update = b.addRunArtifact(update_gap);
        run_update.addArg("--summary");
        run_update.addArg(summary);
        step_update_gap.dependOn(&run_update.step);
    }

    // Tests
    const test_step = b.step("test", "Run unit tests");
    const filter_opt = b.option([]const u8, "test-filter", "Filter tests by substring");
    const filter = user_filter orelse (filter_opt orelse null);
    const legacy_tests = b.option(bool, "legacy-tests", "Run legacy tests in quic.zig") orelse false;
    const cc_opt = b.option([]const u8, "cc", "Congestion control: newreno (default) or cubic");

    // Expose TLS/crypto/packet modules
    const quic_tls_mod = mkModule(b, "src/quic/tls/key_schedule.zig");
    const quic_crypto_mod = mkModule(b, "src/quic/crypto_quic.zig");
    const quic_packet_mod = mkModule(b, "src/quic/packet.zig");
    quic_packet_mod.addImport("quic_tls", quic_tls_mod);
    quic_packet_mod.addImport("quic_crypto", quic_crypto_mod);
    // Ensure crypto module can import the key schedule
    quic_crypto_mod.addImport("quic_tls", quic_tls_mod);

    // TLS/X.509 modules
    const tls13_mod = mkModule(b, "src/quic/tls/tls13.zig");
    tls13_mod.addImport("quic_tls", quic_tls_mod);
    const asn1_mod = mkModule(b, "src/quic/tls/asn1.zig");
    const x509_mod = mkModule(b, "src/quic/tls/x509.zig");
    _ = asn1_mod;

    // Varint/frame
    const quic_varint_mod = mkModule(b, "src/quic/varint.zig");
    const quic_frame_mod = mkModule(b, "src/quic/frame.zig");
    quic_frame_mod.addImport("quic_varint", quic_varint_mod);
    quic_packet_mod.addImport("quic_varint", quic_varint_mod);

    // Recovery
    const quic_recovery_mod = mkModule(b, "src/quic/recovery.zig");
    quic_recovery_mod.addImport("quic_frame", quic_frame_mod);
    if (cc_opt) |_| {
        // Placeholder: runtime selection occurs via config; both controllers are in same module
    }

    // Connection/TP
    const quic_conn_mod = mkModule(b, "src/quic/conn.zig");
    quic_conn_mod.addImport("quic_packet", quic_packet_mod);
    quic_conn_mod.addImport("quic_frame", quic_frame_mod);
    quic_conn_mod.addImport("quic_tls13", tls13_mod);
    quic_conn_mod.addImport("quic_varint", quic_varint_mod);
    const quic_transport_params_mod = mkModule(b, "src/quic/transport_params.zig");
    quic_transport_params_mod.addImport("quic_varint", quic_varint_mod);

    // Endpoint module for socket/event-loop tests
    const quic_endpoint_mod = mkModule(b, "src/quic/endpoint.zig");
    quic_endpoint_mod.addImport("quic_conn", quic_conn_mod);
    quic_endpoint_mod.addImport("quic_packet", quic_packet_mod);
    quic_endpoint_mod.addImport("quic_frame", quic_frame_mod);
    quic_endpoint_mod.addImport("quic_tls13", tls13_mod);
    quic_endpoint_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_endpoint_mod.addImport("quic_varint", quic_varint_mod);
    quic_endpoint_mod.addImport("quic_tls", quic_tls_mod);

    // Public API module (reuse everywhere)
    const quic_api_mod = mkModule(b, "src/quic/api.zig");
    quic_api_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_api_mod.addImport("quic_frame", quic_frame_mod);
    quic_api_mod.addImport("quic_varint", quic_varint_mod);
    quic_api_mod.addImport("tls/key_schedule.zig", quic_tls_mod);
    quic_api_mod.addImport("quic_tls", quic_tls_mod);
    quic_api_mod.addImport("quic_tls13", tls13_mod);
    quic_api_mod.addImport("quic_conn", quic_conn_mod);
    quic_api_mod.addImport("quic_packet", quic_packet_mod);

    // Export named module for dependents: @import("quic")
    const quic_mod = b.addModule("quic", .{ .root_source_file = rp("src/quic/api.zig") });
    quic_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_mod.addImport("quic_frame", quic_frame_mod);
    quic_mod.addImport("quic_varint", quic_varint_mod);
    quic_mod.addImport("quic_tls", quic_tls_mod);
    quic_mod.addImport("quic_tls13", tls13_mod);
    quic_mod.addImport("quic_conn", quic_conn_mod);
    quic_mod.addImport("quic_packet", quic_packet_mod);

    // CLI binaries (scaffold): quic-client, quic-server
    const quic_client = b.addExecutable(.{ .name = "quic-client", .root_source_file = rp("cmd/quic-client.zig"), .target = target, .optimize = optimize });
    quic_client.root_module.addImport("quic_api", quic_api_mod);
    const install_quic_client = b.addInstallArtifact(quic_client, .{});

    const quic_server = b.addExecutable(.{ .name = "quic-server", .root_source_file = rp("cmd/quic-server.zig"), .target = target, .optimize = optimize });
    quic_server.root_module.addImport("quic_api", quic_api_mod);
    const install_quic_server = b.addInstallArtifact(quic_server, .{});

    const cli_step = b.step("cli", "Build QUIC CLI client/server");
    cli_step.dependOn(&install_quic_client.step);
    cli_step.dependOn(&install_quic_server.step);

    // Filtering
    if (filter) |f| {
        if (std.mem.containsAtLeast(u8, f, 1, "tls_key_schedule_kat")) {
            const test_tls_only = b.addTest(.{ .root_source_file = rp("tests/test_tls_key_schedule.zig"), .target = target, .optimize = optimize });
            test_tls_only.root_module.addImport("quic_tls", quic_tls_mod);
            const run_test_tls_only = b.addRunArtifact(test_tls_only);
            test_step.dependOn(&run_test_tls_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "timers")) {
            const test_timers_only = b.addTest(.{ .root_source_file = rp("tests/test_timers.zig"), .target = target, .optimize = optimize });
            test_timers_only.root_module.addImport("quic_api", quic_api_mod);
            test_timers_only.root_module.addImport("quic_conn", quic_conn_mod);
            test_timers_only.root_module.addImport("quic_tls13", tls13_mod);
            const run_test_timers_only = b.addRunArtifact(test_timers_only);
            test_step.dependOn(&run_test_timers_only.step);
            return;
        }
    }

    if (!legacy_tests) {
        const test_tls = b.addTest(.{ .root_source_file = rp("tests/test_tls_key_schedule.zig"), .target = target, .optimize = optimize });
        test_tls.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_tls = b.addRunArtifact(test_tls);
        test_step.dependOn(&run_test_tls.step);

        const test_tls_hs = b.addTest(.{ .root_source_file = rp("tests/test_tls_handshake_secrets.zig"), .target = target, .optimize = optimize });
        test_tls_hs.root_module.addImport("quic_tls13", tls13_mod);
        test_tls_hs.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_tls_hs = b.addRunArtifact(test_tls_hs);
        test_step.dependOn(&run_test_tls_hs.step);

        const test_initial = b.addTest(.{ .root_source_file = rp("tests/test_initial_protect.zig"), .target = target, .optimize = optimize });
        test_initial.root_module.addImport("quic_tls", quic_tls_mod);
        test_initial.root_module.addImport("quic_crypto", quic_crypto_mod);
        const run_test_initial = b.addRunArtifact(test_initial);
        test_step.dependOn(&run_test_initial.step);

        const test_rfc_a1 = b.addTest(.{ .root_source_file = rp("tests/test_rfc9001_a1_initial.zig"), .target = target, .optimize = optimize });
        test_rfc_a1.root_module.addImport("quic_tls", quic_tls_mod);
        test_rfc_a1.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_rfc_a1.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_rfc_a1 = b.addRunArtifact(test_rfc_a1);
        test_step.dependOn(&run_test_rfc_a1.step);

        const test_rfc_a3 = b.addTest(.{ .root_source_file = rp("tests/test_rfc9001_a3_server_initial.zig"), .target = target, .optimize = optimize });
        test_rfc_a3.root_module.addImport("quic_tls", quic_tls_mod);
        test_rfc_a3.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_rfc_a3.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_rfc_a3 = b.addRunArtifact(test_rfc_a3);
        test_step.dependOn(&run_test_rfc_a3.step);

        const test_crypto_extract = b.addTest(.{ .root_source_file = rp("tests/test_crypto_extract.zig"), .target = target, .optimize = optimize });
        test_crypto_extract.root_module.addImport("quic_tls", quic_tls_mod);
        test_crypto_extract.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_crypto_extract.root_module.addImport("quic_packet", quic_packet_mod);
        test_crypto_extract.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_crypto_extract = b.addRunArtifact(test_crypto_extract);
        test_step.dependOn(&run_test_crypto_extract.step);

        const test_recovery = b.addTest(.{ .root_source_file = rp("tests/test_recovery.zig"), .target = target, .optimize = optimize });
        test_recovery.root_module.addImport("quic_recovery", quic_recovery_mod);
        test_recovery.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_recovery = b.addRunArtifact(test_recovery);
        test_step.dependOn(&run_test_recovery.step);

        const test_loop = b.addTest(.{ .root_source_file = rp("tests/test_initial_handshake_loop.zig"), .target = target, .optimize = optimize });
        test_loop.root_module.addImport("quic_tls", quic_tls_mod);
        test_loop.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_loop.root_module.addImport("quic_packet", quic_packet_mod);
        test_loop.root_module.addImport("quic_frame", quic_frame_mod);
        test_loop.root_module.addImport("quic_tls13", tls13_mod);
        test_loop.root_module.addImport("quic_varint", quic_varint_mod);
        const run_test_loop = b.addRunArtifact(test_loop);
        test_step.dependOn(&run_test_loop.step);

        const test_sh = b.addTest(.{ .root_source_file = rp("tests/test_shortrtt_roundtrip.zig"), .target = target, .optimize = optimize });
        test_sh.root_module.addImport("quic_tls13", tls13_mod);
        test_sh.root_module.addImport("quic_packet", quic_packet_mod);
        test_sh.root_module.addImport("quic_crypto", quic_crypto_mod);
        const run_test_sh = b.addRunArtifact(test_sh);
        test_step.dependOn(&run_test_sh.step);

        const test_pn = b.addTest(.{ .root_source_file = rp("tests/test_pn_expansion.zig"), .target = target, .optimize = optimize });
        test_pn.root_module.addImport("quic_tls13", tls13_mod);
        test_pn.root_module.addImport("quic_conn", quic_conn_mod);
        const run_test_pn = b.addRunArtifact(test_pn);
        test_step.dependOn(&run_test_pn.step);

        const test_tp = b.addTest(.{ .root_source_file = rp("tests/test_transport_params.zig"), .target = target, .optimize = optimize });
        test_tp.root_module.addImport("quic_transport_params", quic_transport_params_mod);
        const run_test_tp = b.addRunArtifact(test_tp);
        test_step.dependOn(&run_test_tp.step);

        const test_timers = b.addTest(.{ .root_source_file = rp("tests/test_timers.zig"), .target = target, .optimize = optimize });
        test_timers.root_module.addImport("quic_api", quic_api_mod);
        test_timers.root_module.addImport("quic_conn", quic_conn_mod);
        test_timers.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_timers = b.addRunArtifact(test_timers);
        test_step.dependOn(&run_test_timers.step);

        const test_vn = b.addTest(.{ .root_source_file = rp("tests/test_version_negotiation.zig"), .target = target, .optimize = optimize });
        test_vn.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_vn = b.addRunArtifact(test_vn);
        test_step.dependOn(&run_test_vn.step);

        // New: Retry issuance and amplification gating tests
        const test_retry = b.addTest(.{ .root_source_file = rp("tests/test_retry.zig"), .target = target, .optimize = optimize });
        test_retry.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_retry.root_module.addImport("quic_packet", quic_packet_mod);
        test_retry.root_module.addImport("quic_varint", quic_varint_mod);
        test_retry.root_module.addImport("quic_tls", quic_tls_mod);
        test_retry.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_retry = b.addRunArtifact(test_retry);
        test_step.dependOn(&run_test_retry.step);

        const test_retry_tamper = b.addTest(.{ .root_source_file = rp("tests/test_retry_tamper.zig"), .target = target, .optimize = optimize });
        test_retry_tamper.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_retry_tamper.root_module.addImport("quic_packet", quic_packet_mod);
        test_retry_tamper.root_module.addImport("quic_varint", quic_varint_mod);
        test_retry_tamper.root_module.addImport("quic_tls", quic_tls_mod);
        test_retry_tamper.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_retry_tamper = b.addRunArtifact(test_retry_tamper);
        test_step.dependOn(&run_test_retry_tamper.step);

        const test_amp = b.addTest(.{ .root_source_file = rp("tests/test_amplification.zig"), .target = target, .optimize = optimize });
        test_amp.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_amp.root_module.addImport("quic_packet", quic_packet_mod);
        test_amp.root_module.addImport("quic_varint", quic_varint_mod);
        test_amp.root_module.addImport("quic_tls", quic_tls_mod);
        test_amp.root_module.addImport("quic_frame", quic_frame_mod);
        test_amp.root_module.addImport("quic_crypto", quic_crypto_mod);
        const run_test_amp = b.addRunArtifact(test_amp);
        test_step.dependOn(&run_test_amp.step);

        // ALPN enforcement and getter tests
        const test_alpn = b.addTest(.{ .root_source_file = rp("tests/test_alpn.zig"), .target = target, .optimize = optimize });
        test_alpn.root_module.addImport("quic_api", quic_api_mod);
        test_alpn.root_module.addImport("quic_conn", quic_conn_mod);
        test_alpn.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_alpn = b.addRunArtifact(test_alpn);
        test_step.dependOn(&run_test_alpn.step);

        // TLS SNI negative/allow_insecure tests
        const test_tls_sni = b.addTest(.{ .root_source_file = rp("tests/test_tls_sni.zig"), .target = target, .optimize = optimize });
        test_tls_sni.root_module.addImport("quic_x509", x509_mod);
        const run_test_tls_sni = b.addRunArtifact(test_tls_sni);
        test_step.dependOn(&run_test_tls_sni.step);
    } else {
        const test_quic = b.addTest(.{ .root_source_file = rp("quic.zig"), .target = target, .optimize = optimize });
        const run_test_quic = b.addRunArtifact(test_quic);
        test_step.dependOn(&run_test_quic.step);
    }

    // Fuzzers
    const fuzz_varint = b.addExecutable(.{ .name = "fuzz_varint", .root_source_file = rp("fuzz/fuzz_varint.zig"), .target = target, .optimize = optimize });
    const fuzz_frame = b.addExecutable(.{ .name = "fuzz_frame_parse", .root_source_file = rp("fuzz/fuzz_frame_parse.zig"), .target = target, .optimize = optimize });
    const fuzz_vn = b.addExecutable(.{ .name = "fuzz_vn_parse", .root_source_file = rp("fuzz/fuzz_vn_parse.zig"), .target = target, .optimize = optimize });
    fuzz_varint.root_module.addImport("quic_varint", quic_varint_mod);
    fuzz_frame.root_module.addImport("quic_frame", quic_frame_mod);
    fuzz_frame.root_module.addImport("quic_varint", quic_varint_mod);
    fuzz_vn.root_module.addImport("quic_packet", quic_packet_mod);
    const install_fuzz_varint = b.addInstallArtifact(fuzz_varint, .{});
    const install_fuzz_frame = b.addInstallArtifact(fuzz_frame, .{});
    const install_fuzz_vn = b.addInstallArtifact(fuzz_vn, .{});
    const fuzz_step = b.step("fuzz", "Build fuzzers");
    fuzz_step.dependOn(&install_fuzz_varint.step);
    fuzz_step.dependOn(&install_fuzz_frame.step);
    fuzz_step.dependOn(&install_fuzz_vn.step);

    // Benchmarks
    const bench = b.addExecutable(.{ .name = "quic-bench", .root_source_file = rp("bench/main.zig"), .target = target, .optimize = optimize });
    bench.root_module.addImport("quic_varint", quic_varint_mod);
    const install_bench = b.addInstallArtifact(bench, .{});
    const bench_step = b.step("bench", "Build benchmarks");
    bench_step.dependOn(&install_bench.step);
}
