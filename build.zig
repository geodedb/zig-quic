// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

fn mkModule(b: *std.Build, path: []const u8) *std.Build.Module {
    return b.createModule(.{ .root_source_file = b.path(path) });
}

fn addExe(b: *std.Build, name: []const u8, path: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    var exe = b.addExecutable(.{ .name = name, .root_module = b.createModule(.{ .root_source_file = b.path(path), .target = target, .optimize = optimize }) });

    // Link OpenSSL for crypto operations (required for QUIC AEAD compatibility)
    // Note: On Windows, OpenSSL is optional since it may not be available on CI runners
    if (target.result.os.tag != .windows) {
        exe.linkSystemLibrary("ssl");
        exe.linkSystemLibrary("crypto");
    }
    exe.linkLibC();

    if (target.result.os.tag == .windows) {
        exe.linkSystemLibrary("ws2_32");
    }
    return exe;
}

fn addTst(
    b: *std.Build,
    testlog_mod: *std.Build.Module,
    path: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    const root_mod = b.createModule(.{ .root_source_file = b.path(path), .target = target, .optimize = optimize });
    root_mod.addImport("testlog", testlog_mod);
    var tst = b.addTest(.{ .root_module = root_mod });

    // Link OpenSSL for crypto operations (required for QUIC AEAD compatibility)
    // Note: On Windows, OpenSSL is optional since it may not be available on CI runners
    if (target.result.os.tag != .windows) {
        tst.linkSystemLibrary("ssl");
        tst.linkSystemLibrary("crypto");
    }
    tst.linkLibC();

    if (target.result.os.tag == .windows) {
        tst.linkSystemLibrary("ws2_32");
    }
    return tst;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize_base = b.standardOptimizeOption(.{});
    const release_safe = b.option(bool, "release-safe", "Build with ReleaseSafe optimization (convenience flag)") orelse false;
    const optimize: std.builtin.OptimizeMode = if (release_safe) .ReleaseSafe else optimize_base;
    _ = b.option(bool, "xdp", "Enable XDP path (no-op placeholder)") orelse false;

    // Spice parallelism option
    const enable_spice = b.option(bool, "spice", "Enable spice-based parallelism") orelse true;

    // Build options module for compile-time feature flags
    const build_options = b.addOptions();
    build_options.addOption(bool, "enable_spice", enable_spice);

    // Get spice dependency if enabled
    const spice_mod: ?*std.Build.Module = if (enable_spice) blk: {
        const spice_dep = b.dependency("spice", .{
            .target = target,
            .optimize = optimize,
        });
        break :blk spice_dep.module("spice");
    } else null;

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
    // TODO: Update to new build API when migrating past current Zig version; for now use root_source_file field.
    const varint_exe = addExe(b, "quic-varint", "tools/varint_tool.zig", target, optimize);
    const install_varint = b.addInstallArtifact(varint_exe, .{});

    // tools: update-gap, doccheck
    const update_gap = addExe(b, "update-gap", "tools/update_gap.zig", target, optimize);
    const install_update_gap = b.addInstallArtifact(update_gap, .{});

    const doccheck = addExe(b, "doccheck", "tools/doccheck.zig", target, optimize);
    const install_doccheck = b.addInstallArtifact(doccheck, .{});

    const tools_step = b.step("tools", "Build CLI tools");
    tools_step.dependOn(&install_varint.step);
    tools_step.dependOn(&install_update_gap.step);
    tools_step.dependOn(&install_doccheck.step);

    // Add interop runner tool
    const interop_runner = addExe(b, "interop-runner", "tools/interop_runner.zig", target, optimize);
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
    const full_test_graph = b.option(bool, "full-test-graph", "Run full per-file test graph (slower, maximum coverage)") orelse false;
    const cc_opt = b.option([]const u8, "cc", "Congestion control: newreno (default) or cubic");

    // Expose TLS/crypto/packet modules
    const byteorder_mod = mkModule(b, "src/byteorder/byteorder.zig");

    // ========================================================================
    // External TLS Library (from build.zig.zon dependency)
    // ========================================================================
    // Import TLS modules from the external tls library instead of vendored implementation
    const tls_dep = b.dependency("tls", .{
        .target = target,
        .optimize = optimize,
    });

    // Get TLS modules from the external dependency (only the ones actually used)
    const quic_tls_mod = tls_dep.module("quic_tls");
    const tls13_mod = tls_dep.module("tls13");
    const alert_mod = tls_dep.module("alert");
    const sig_mod = tls_dep.module("sig");
    const x509_mod = tls_dep.module("x509");
    const zero_rtt_mod = tls_dep.module("zero_rtt");
    const tls_record_mod = tls_dep.module("record");

    // QUIC crypto and packet modules
    const quic_crypto_mod = mkModule(b, "src/quic/crypto_quic.zig");
    // Ensure crypto module can import the key schedule
    quic_crypto_mod.addImport("quic_tls", quic_tls_mod);

    // Varint module (needed by packet and frame modules)
    const quic_varint_mod = mkModule(b, "src/quic/varint.zig");
    quic_varint_mod.addImport("byteorder", byteorder_mod);

    // Version negotiation module (needed by packet and connection modules)
    const quic_version_mod = mkModule(b, "src/quic/version.zig");

    // Token module (Retry token encode/verify)
    const quic_token_mod = mkModule(b, "src/quic/token.zig");
    quic_token_mod.addImport("byteorder", byteorder_mod);

    // Logger module for QUIC library (local QUIC logger, not vendored TLS logger)
    const quic_logger_mod = mkModule(b, "src/quic/logger.zig");

    // ========================================================================
    // Packet Sub-Modules (Phase 7 Refactoring)
    // ========================================================================
    const packet_types_mod = mkModule(b, "src/quic/packet/types.zig");

    const packet_header_mod = mkModule(b, "src/quic/packet/header.zig");
    packet_header_mod.addImport("types", packet_types_mod);
    packet_header_mod.addImport("quic_varint", quic_varint_mod);

    // Packet coordinator module (imports legacy packet.zig and new submodules)
    const quic_packet_mod = mkModule(b, "src/quic/packet/packet.zig");
    quic_packet_mod.addImport("types", packet_types_mod);
    quic_packet_mod.addImport("header", packet_header_mod);
    // Import legacy packet.zig for current implementations
    const quic_packet_legacy_mod = mkModule(b, "src/quic/packet.zig");
    quic_packet_legacy_mod.addImport("quic_tls", quic_tls_mod);
    quic_packet_legacy_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_packet_legacy_mod.addImport("quic_varint", quic_varint_mod);
    quic_packet_legacy_mod.addImport("quic_version", quic_version_mod);
    quic_packet_legacy_mod.addImport("quic_logger", quic_logger_mod);
    quic_packet_mod.addImport("../packet.zig", quic_packet_legacy_mod);

    // ========================================================================
    // Frame Sub-Modules (Phase 6 Refactoring)
    // ========================================================================
    const frame_types_mod = mkModule(b, "src/quic/frame/types.zig");

    const frame_misc_mod = mkModule(b, "src/quic/frame/misc.zig");
    frame_misc_mod.addImport("types", frame_types_mod);
    frame_misc_mod.addImport("quic_varint", quic_varint_mod);

    const frame_crypto_mod = mkModule(b, "src/quic/frame/crypto.zig");
    frame_crypto_mod.addImport("types", frame_types_mod);
    frame_crypto_mod.addImport("quic_varint", quic_varint_mod);

    const frame_stream_mod = mkModule(b, "src/quic/frame/stream.zig");
    frame_stream_mod.addImport("types", frame_types_mod);
    frame_stream_mod.addImport("quic_varint", quic_varint_mod);

    const frame_ack_mod = mkModule(b, "src/quic/frame/ack.zig");
    frame_ack_mod.addImport("types", frame_types_mod);
    frame_ack_mod.addImport("quic_varint", quic_varint_mod);

    const frame_path_mod = mkModule(b, "src/quic/frame/path.zig");
    frame_path_mod.addImport("types", frame_types_mod);

    const frame_connection_mgmt_mod = mkModule(b, "src/quic/frame/connection_mgmt.zig");
    frame_connection_mgmt_mod.addImport("types", frame_types_mod);
    frame_connection_mgmt_mod.addImport("quic_varint", quic_varint_mod);

    const frame_flow_control_mod = mkModule(b, "src/quic/frame/flow_control.zig");
    frame_flow_control_mod.addImport("types", frame_types_mod);
    frame_flow_control_mod.addImport("quic_varint", quic_varint_mod);

    const frame_datagram_mod = mkModule(b, "src/quic/frame/datagram.zig");
    frame_datagram_mod.addImport("types", frame_types_mod);
    frame_datagram_mod.addImport("quic_varint", quic_varint_mod);

    // Frame coordinator module
    const quic_frame_mod = mkModule(b, "src/quic/frame/frame.zig");
    quic_frame_mod.addImport("types", frame_types_mod);
    quic_frame_mod.addImport("misc", frame_misc_mod);
    quic_frame_mod.addImport("crypto", frame_crypto_mod);
    quic_frame_mod.addImport("stream", frame_stream_mod);
    quic_frame_mod.addImport("ack", frame_ack_mod);
    quic_frame_mod.addImport("path", frame_path_mod);
    quic_frame_mod.addImport("connection_mgmt", frame_connection_mgmt_mod);
    quic_frame_mod.addImport("flow_control", frame_flow_control_mod);
    quic_frame_mod.addImport("datagram", frame_datagram_mod);
    quic_frame_mod.addImport("quic_varint", quic_varint_mod);

    quic_packet_mod.addImport("quic_varint", quic_varint_mod);

    // Local QUIC transport params (separate from vendored TLS transport params)
    const quic_transport_params_mod = mkModule(b, "src/quic/transport_params.zig");
    quic_transport_params_mod.addImport("quic_varint", quic_varint_mod);

    // QUIC configuration module
    const quic_config_mod = mkModule(b, "src/quic/config.zig");

    // Note: tls13_mod uses ztls_transport_params_mod from vendor/ztls (defined above)

    // ========================================================================
    // Recovery Sub-Modules (Phase 8 Refactoring)
    // ========================================================================
    const recovery_types_mod = mkModule(b, "src/quic/recovery/types.zig");

    const recovery_rtt_mod = mkModule(b, "src/quic/recovery/rtt.zig");

    const recovery_loss_detection_mod = mkModule(b, "src/quic/recovery/loss_detection.zig");
    recovery_loss_detection_mod.addImport("quic_frame", quic_frame_mod);

    const recovery_congestion_mod = mkModule(b, "src/quic/recovery/congestion.zig");

    // Recovery coordinator module
    const quic_recovery_mod = mkModule(b, "src/quic/recovery/recovery.zig");
    quic_recovery_mod.addImport("types", recovery_types_mod);
    quic_recovery_mod.addImport("rtt.zig", recovery_rtt_mod);
    quic_recovery_mod.addImport("loss_detection.zig", recovery_loss_detection_mod);
    quic_recovery_mod.addImport("congestion.zig", recovery_congestion_mod);
    quic_recovery_mod.addImport("quic_frame", quic_frame_mod);
    if (cc_opt) |_| {
        // Placeholder: runtime selection occurs via config; both controllers are in same module
    }

    // Add logger to modules that need it
    quic_crypto_mod.addImport("quic_logger", quic_logger_mod);
    quic_packet_mod.addImport("quic_logger", quic_logger_mod);
    quic_recovery_mod.addImport("quic_logger", quic_logger_mod);

    // Note: alert_mod, zero_rtt_mod, and tls logger are now imported from vendor/ztls above

    // ========================================================================
    // Connection Sub-Modules (Phase 1 Refactoring)
    // ========================================================================
    const conn_types_mod = mkModule(b, "src/quic/connection/types.zig");
    conn_types_mod.addImport("byteorder", byteorder_mod);

    const conn_crypto_buffer_mod = mkModule(b, "src/quic/connection/crypto_buffer.zig");
    conn_crypto_buffer_mod.addImport("quic_logger", quic_logger_mod);

    const conn_packet_number_mod = mkModule(b, "src/quic/connection/packet_number.zig");
    conn_packet_number_mod.addImport("quic_frame", quic_frame_mod);

    const conn_ack_mod = mkModule(b, "src/quic/connection/ack.zig");
    conn_ack_mod.addImport("quic_frame", quic_frame_mod);

    const conn_stream_mod = mkModule(b, "src/quic/connection/stream.zig");

    const conn_connection_id_mod = mkModule(b, "src/quic/connection/connection_id.zig");
    conn_connection_id_mod.addImport("types", conn_types_mod);
    conn_connection_id_mod.addImport("quic_tls", quic_tls_mod);

    const conn_handshake_mod = mkModule(b, "src/quic/connection/handshake.zig");

    const conn_path_mod = mkModule(b, "src/quic/connection/path.zig");

    const conn_amplification_mod = mkModule(b, "src/quic/connection/amplification.zig");

    const conn_pmtud_mod = mkModule(b, "src/quic/connection/pmtud.zig");

    const conn_limits_mod = mkModule(b, "src/quic/connection/limits.zig");

    const conn_flow_control_mod = mkModule(b, "src/quic/connection/flow_control.zig");

    const conn_error_mod = mkModule(b, "src/quic/connection/error.zig");

    const conn_idle_mod = mkModule(b, "src/quic/connection/idle.zig");

    const conn_connection_mod = mkModule(b, "src/quic/connection/connection.zig");
    // Connection coordinator imports all sub-modules
    conn_connection_mod.addImport("types", conn_types_mod);
    conn_connection_mod.addImport("crypto_buffer", conn_crypto_buffer_mod);
    conn_connection_mod.addImport("packet_number", conn_packet_number_mod);
    conn_connection_mod.addImport("ack", conn_ack_mod);
    conn_connection_mod.addImport("stream", conn_stream_mod);
    conn_connection_mod.addImport("connection_id", conn_connection_id_mod);
    conn_connection_mod.addImport("handshake", conn_handshake_mod);
    conn_connection_mod.addImport("path", conn_path_mod);
    conn_connection_mod.addImport("amplification", conn_amplification_mod);
    conn_connection_mod.addImport("pmtud", conn_pmtud_mod);
    conn_connection_mod.addImport("limits", conn_limits_mod);
    conn_connection_mod.addImport("flow_control", conn_flow_control_mod);
    conn_connection_mod.addImport("error", conn_error_mod);
    conn_connection_mod.addImport("idle", conn_idle_mod);

    // ========================================================================
    // Endpoint Sub-Modules (Phase 2 Refactoring)
    // ========================================================================
    // Note: endpoint modules defined after quic_conn_mod is created below

    // Connection/TP
    const quic_conn_mod = mkModule(b, "src/quic/conn.zig");
    quic_conn_mod.addImport("quic_packet", quic_packet_mod);
    quic_conn_mod.addImport("quic_frame", quic_frame_mod);
    quic_conn_mod.addImport("quic_tls13", tls13_mod);
    quic_conn_mod.addImport("quic_varint", quic_varint_mod);
    quic_conn_mod.addImport("quic_tls", quic_tls_mod);
    quic_conn_mod.addImport("quic_recovery", quic_recovery_mod);
    quic_conn_mod.addImport("quic_logger", quic_logger_mod);
    quic_conn_mod.addImport("byteorder", byteorder_mod);
    quic_conn_mod.addImport("quic_version", quic_version_mod);
    // Make transport params available to connection and endpoint modules
    quic_conn_mod.addImport("quic_transport_params", quic_transport_params_mod);
    // Phase 5: conn.zig now imports connection/* modules directly via file paths to avoid diamond dependencies

    // Now define endpoint modules (they need quic_conn_mod)
    const endpoint_types_mod = mkModule(b, "src/quic/endpoint/types.zig");
    endpoint_types_mod.addImport("quic_conn", quic_conn_mod);

    const endpoint_timer_mod = mkModule(b, "src/quic/endpoint/timer.zig");
    endpoint_timer_mod.addImport("types", endpoint_types_mod);

    const endpoint_lookup_mod = mkModule(b, "src/quic/endpoint/lookup.zig");
    endpoint_lookup_mod.addImport("types", endpoint_types_mod);
    endpoint_lookup_mod.addImport("quic_conn", quic_conn_mod);

    const endpoint_io_mod = mkModule(b, "src/quic/endpoint/io.zig");
    endpoint_io_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_io_mod.addImport("quic_logger", quic_logger_mod);

    const endpoint_client_mod = mkModule(b, "src/quic/endpoint/client.zig");
    endpoint_client_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_client_mod.addImport("quic_packet", quic_packet_mod);
    endpoint_client_mod.addImport("quic_frame", quic_frame_mod);
    endpoint_client_mod.addImport("quic_tls", quic_tls_mod);
    endpoint_client_mod.addImport("types", endpoint_types_mod);
    endpoint_client_mod.addImport("quic_logger", quic_logger_mod);
    // Note: handshake_integration import added later after endpoint_handshake_integration_mod is declared

    const endpoint_server_mod = mkModule(b, "src/quic/endpoint/server.zig");
    endpoint_server_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_server_mod.addImport("types", endpoint_types_mod);
    endpoint_server_mod.addImport("config", quic_config_mod);
    endpoint_server_mod.addImport("transport_params", quic_transport_params_mod);
    endpoint_server_mod.addImport("packet", quic_packet_legacy_mod);
    endpoint_server_mod.addImport("x509", x509_mod);
    endpoint_server_mod.addImport("sig", sig_mod);
    endpoint_server_mod.addImport("quic_logger", quic_logger_mod);

    const endpoint_utils_mod = mkModule(b, "src/quic/endpoint/utils.zig");
    endpoint_utils_mod.addImport("quic_conn", quic_conn_mod);

    const endpoint_transport_mod = mkModule(b, "src/quic/endpoint/transport.zig");
    endpoint_transport_mod.addImport("quic_conn", quic_conn_mod);

    const endpoint_udp_transport_mod = mkModule(b, "src/quic/endpoint/udp_transport.zig");
    endpoint_udp_transport_mod.addImport("transport.zig", endpoint_transport_mod);
    endpoint_udp_transport_mod.addImport("conn.zig", quic_conn_mod);

    const endpoint_incoming_mod = mkModule(b, "src/quic/endpoint/incoming.zig");
    endpoint_incoming_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_incoming_mod.addImport("packet", quic_packet_legacy_mod);
    endpoint_incoming_mod.addImport("types", endpoint_types_mod);
    endpoint_incoming_mod.addImport("vendor_ztls_key_schedule", quic_tls_mod);
    endpoint_incoming_mod.addImport("crypto_quic", quic_crypto_mod);
    endpoint_incoming_mod.addImport("frame", quic_frame_mod);
    endpoint_incoming_mod.addImport("varint", quic_varint_mod);
    endpoint_incoming_mod.addImport("token", quic_token_mod);
    endpoint_incoming_mod.addImport("transport_params", quic_transport_params_mod);
    endpoint_incoming_mod.addImport("x509", x509_mod);
    endpoint_incoming_mod.addImport("sig", sig_mod);
    endpoint_incoming_mod.addImport("lookup", endpoint_lookup_mod);
    endpoint_incoming_mod.addImport("quic_logger", quic_logger_mod);

    const endpoint_handshake_integration_mod = mkModule(b, "src/quic/endpoint/handshake_integration.zig");
    endpoint_handshake_integration_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_handshake_integration_mod.addImport("packet", quic_packet_legacy_mod);
    endpoint_handshake_integration_mod.addImport("frame", quic_frame_mod);
    endpoint_handshake_integration_mod.addImport("crypto_quic", quic_crypto_mod);
    endpoint_handshake_integration_mod.addImport("transport_params", quic_transport_params_mod);
    endpoint_handshake_integration_mod.addImport("vendor_ztls_tls13", tls13_mod);
    endpoint_handshake_integration_mod.addImport("vendor_ztls_key_schedule", quic_tls_mod);
    endpoint_handshake_integration_mod.addImport("quic_logger", quic_logger_mod);

    // Add handshake_integration import to endpoint_client_mod (declared earlier at line ~388)
    endpoint_client_mod.addImport("handshake_integration", endpoint_handshake_integration_mod);
    endpoint_client_mod.addImport("quic_tls13", tls13_mod);

    const endpoint_pto_mod = mkModule(b, "src/quic/endpoint/pto.zig");
    endpoint_pto_mod.addImport("types", endpoint_types_mod);
    endpoint_pto_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_pto_mod.addImport("quic_packet", quic_packet_mod);
    endpoint_pto_mod.addImport("quic_frame", quic_frame_mod);
    endpoint_pto_mod.addImport("quic_tls", quic_tls_mod);
    endpoint_pto_mod.addImport("quic_logger", quic_logger_mod);

    const endpoint_lifecycle_mod = mkModule(b, "src/quic/endpoint/lifecycle.zig");
    endpoint_lifecycle_mod.addImport("types", endpoint_types_mod);
    endpoint_lifecycle_mod.addImport("quic_conn", quic_conn_mod);

    const endpoint_frame_handler_mod = mkModule(b, "src/quic/endpoint/frame_handler.zig");
    endpoint_frame_handler_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_frame_handler_mod.addImport("frame", quic_frame_mod);
    endpoint_frame_handler_mod.addImport("packet", quic_packet_legacy_mod);
    endpoint_frame_handler_mod.addImport("quic_logger", quic_logger_mod);

    const endpoint_endpoint_mod = mkModule(b, "src/quic/endpoint/endpoint.zig");
    // Endpoint coordinator imports all sub-modules
    endpoint_endpoint_mod.addImport("types", endpoint_types_mod);
    endpoint_endpoint_mod.addImport("timer", endpoint_timer_mod);
    endpoint_endpoint_mod.addImport("lookup", endpoint_lookup_mod);
    endpoint_endpoint_mod.addImport("io", endpoint_io_mod);
    endpoint_endpoint_mod.addImport("client", endpoint_client_mod);
    endpoint_endpoint_mod.addImport("server", endpoint_server_mod);
    endpoint_endpoint_mod.addImport("incoming", endpoint_incoming_mod);
    endpoint_endpoint_mod.addImport("pto", endpoint_pto_mod);

    // Endpoint module for socket/event-loop tests
    const loop_backend_mod = mkModule(b, "src/quic/loop_backend.zig");

    // Add config import to handshake_integration_mod, frame_handler_mod, and incoming_mod now that quic_config_mod is defined
    endpoint_handshake_integration_mod.addImport("config", quic_config_mod);
    endpoint_frame_handler_mod.addImport("config", quic_config_mod);
    endpoint_incoming_mod.addImport("config", quic_config_mod);
    endpoint_incoming_mod.addImport("frame_handler", endpoint_frame_handler_mod);
    endpoint_incoming_mod.addImport("handshake_integration", endpoint_handshake_integration_mod);

    const quic_endpoint_mod = mkModule(b, "src/quic/endpoint.zig");
    quic_endpoint_mod.addImport("types", endpoint_types_mod);
    quic_endpoint_mod.addImport("quic_conn", quic_conn_mod);
    quic_endpoint_mod.addImport("quic_packet", quic_packet_mod);
    quic_endpoint_mod.addImport("quic_frame", quic_frame_mod);
    quic_endpoint_mod.addImport("quic_tls13", tls13_mod);
    quic_endpoint_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_endpoint_mod.addImport("quic_varint", quic_varint_mod);
    quic_endpoint_mod.addImport("quic_tls", quic_tls_mod);
    quic_endpoint_mod.addImport("sig", sig_mod);
    quic_endpoint_mod.addImport("x509", x509_mod);
    quic_endpoint_mod.addImport("quic_recovery", quic_recovery_mod);
    quic_endpoint_mod.addImport("config.zig", quic_config_mod);
    quic_endpoint_mod.addImport("loop_backend.zig", loop_backend_mod);
    quic_endpoint_mod.addImport("quic_transport_params", quic_transport_params_mod);
    quic_endpoint_mod.addImport("quic_logger", quic_logger_mod);
    quic_endpoint_mod.addImport("byteorder", byteorder_mod);
    quic_endpoint_mod.addImport("quic_version", quic_version_mod);
    quic_endpoint_mod.addImport("quic_token", quic_token_mod);
    quic_endpoint_mod.addImport("endpoint/utils.zig", endpoint_utils_mod);
    quic_endpoint_mod.addImport("endpoint/transport.zig", endpoint_transport_mod);
    quic_endpoint_mod.addImport("endpoint/udp_transport.zig", endpoint_udp_transport_mod);
    quic_endpoint_mod.addImport("endpoint/incoming.zig", endpoint_incoming_mod);
    quic_endpoint_mod.addImport("endpoint/frame_handler.zig", endpoint_frame_handler_mod);
    quic_endpoint_mod.addImport("endpoint/lookup.zig", endpoint_lookup_mod);
    quic_endpoint_mod.addImport("endpoint/pto.zig", endpoint_pto_mod);
    quic_endpoint_mod.addImport("endpoint/lifecycle.zig", endpoint_lifecycle_mod);
    quic_endpoint_mod.addImport("endpoint/handshake_integration.zig", endpoint_handshake_integration_mod);
    quic_endpoint_mod.addImport("endpoint/client.zig", endpoint_client_mod);
    quic_endpoint_mod.addImport("endpoint/server.zig", endpoint_server_mod);

    // Public API module (reuse everywhere)
    const quic_api_mod = mkModule(b, "src/quic/api.zig");
    quic_api_mod.addImport("config.zig", quic_config_mod);
    quic_api_mod.addImport("loop_backend.zig", loop_backend_mod);
    quic_api_mod.addImport("quic_endpoint", quic_endpoint_mod);
    quic_api_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_api_mod.addImport("quic_frame", quic_frame_mod);
    quic_api_mod.addImport("quic_varint", quic_varint_mod);
    quic_api_mod.addImport("tls/key_schedule.zig", quic_tls_mod);
    quic_api_mod.addImport("quic_tls", quic_tls_mod);
    quic_api_mod.addImport("quic_tls13", tls13_mod);
    quic_api_mod.addImport("quic_conn", quic_conn_mod);
    quic_api_mod.addImport("quic_packet", quic_packet_mod);
    // Ensure submodule endpoint.zig (imported relatively by api.zig) can import recovery
    quic_api_mod.addImport("quic_recovery", quic_recovery_mod);
    // Add byteorder for endpoint.zig
    quic_api_mod.addImport("byteorder", byteorder_mod);
    // Add transport params for endpoint.zig
    quic_api_mod.addImport("quic_transport_params", quic_transport_params_mod);
    // Add logger for endpoint.zig
    quic_api_mod.addImport("quic_logger", quic_logger_mod);
    // Add version negotiation for endpoint.zig
    quic_api_mod.addImport("quic_version", quic_version_mod);

    // Parallel module for spice-based parallelism
    const parallel_mod = b.addModule("parallel", .{
        .root_source_file = b.path("src/parallel.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = build_options.createModule() },
            .{ .name = "quic/crypto_zig.zig", .module = mkModule(b, "src/quic/crypto_zig.zig") },
        },
    });
    if (spice_mod) |sm| {
        parallel_mod.addImport("spice", sm);
    }

    // Export named module for dependents: @import("quic")
    const quic_mod = b.addModule("quic", .{ .root_source_file = b.path("lib.zig") }); // aggregate export surface
    quic_mod.addImport("quic_endpoint", quic_endpoint_mod);
    quic_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_mod.addImport("quic_frame", quic_frame_mod);
    quic_mod.addImport("quic_varint", quic_varint_mod);
    quic_mod.addImport("quic_tls", quic_tls_mod);
    quic_mod.addImport("quic_tls13", tls13_mod);
    quic_mod.addImport("quic_conn", quic_conn_mod);
    quic_mod.addImport("quic_packet", quic_packet_mod);
    quic_mod.addImport("config.zig", quic_config_mod);
    quic_mod.addImport("quic_transport_params", quic_transport_params_mod);
    quic_mod.addImport("quic_logger", quic_logger_mod);
    quic_mod.addImport("byteorder", byteorder_mod);
    quic_mod.addImport("quic_api", quic_api_mod);
    quic_mod.addImport("parallel", parallel_mod);

    // CLI binaries (scaffold): quic-client, quic-server + debug clients
    const quic_client = addExe(b, "quic-client", "cmd/quic-client.zig", target, optimize);
    quic_client.root_module.addImport("quic_api", quic_api_mod);
    const install_quic_client = b.addInstallArtifact(quic_client, .{});
    b.getInstallStep().dependOn(&install_quic_client.step);

    const quic_client_comprehensive = addExe(b, "quic-client-comprehensive", "cmd/quic-client-comprehensive.zig", target, optimize);
    quic_client_comprehensive.root_module.addImport("quic_api", quic_api_mod);
    const install_quic_client_comprehensive = b.addInstallArtifact(quic_client_comprehensive, .{});

    const quic_server = addExe(b, "quic-server", "cmd/quic-server.zig", target, optimize);
    quic_server.root_module.addImport("quic_api", quic_api_mod);
    const install_quic_server = b.addInstallArtifact(quic_server, .{});
    b.getInstallStep().dependOn(&install_quic_server.step); // Add to default install

    const quic_debug_client = addExe(b, "quic-debug-client", "cmd/quic-debug-client.zig", target, optimize);
    quic_debug_client.root_module.addImport("quic_api", quic_api_mod);
    const install_quic_debug_client = b.addInstallArtifact(quic_debug_client, .{});

    const quic_debug_dgram_client = addExe(b, "quic-debug-dgram-client", "cmd/quic-debug-dgram-client.zig", target, optimize);
    quic_debug_dgram_client.root_module.addImport("quic_api", quic_api_mod);
    const install_quic_debug_dgram_client = b.addInstallArtifact(quic_debug_dgram_client, .{});

    // QNS endpoint binary for interop docker image
    // Minimal HTTP/3 shim module (kept separate from QUIC core)
    const h3_server_mod = mkModule(b, "src/h3/server.zig");
    h3_server_mod.addImport("quic_api", quic_api_mod);
    h3_server_mod.addImport("quic_conn", quic_conn_mod);
    // Export for dependents as named imports
    const h3_mod = b.addModule("h3_server", .{ .root_source_file = b.path("src/h3/server.zig") });
    h3_mod.addImport("quic_api", quic_api_mod);
    h3_mod.addImport("quic_conn", quic_conn_mod);
    const h3_client_mod = b.addModule("h3_client", .{ .root_source_file = b.path("src/h3/client.zig") });
    h3_client_mod.addImport("quic_api", quic_api_mod);
    h3_client_mod.addImport("quic_api", quic_api_mod);
    quic_mod.addImport("h3_server", h3_server_mod);
    quic_mod.addImport("h3_client", h3_client_mod);

    // High-level transport API module
    const transport_mod = mkModule(b, "src/quic/transport.zig");
    transport_mod.addImport("quic_api", quic_api_mod);
    transport_mod.addImport("quic_endpoint", quic_endpoint_mod);
    transport_mod.addImport("quic_conn", quic_conn_mod);
    transport_mod.addImport("quic_crypto", quic_crypto_mod);
    transport_mod.addImport("quic_frame", quic_frame_mod);
    transport_mod.addImport("quic_varint", quic_varint_mod);
    transport_mod.addImport("quic_tls", quic_tls_mod);
    transport_mod.addImport("quic_packet", quic_packet_mod);
    transport_mod.addImport("config.zig", quic_config_mod);
    transport_mod.addImport("loop_backend.zig", loop_backend_mod);
    const transport_public = b.addModule("transport", .{ .root_source_file = b.path("src/quic/transport.zig") });
    transport_public.addImport("quic_api", quic_api_mod);
    transport_public.addImport("quic_endpoint", quic_endpoint_mod);
    transport_public.addImport("quic_conn", quic_conn_mod);
    transport_public.addImport("quic_crypto", quic_crypto_mod);
    transport_public.addImport("quic_frame", quic_frame_mod);
    transport_public.addImport("quic_varint", quic_varint_mod);
    transport_public.addImport("quic_tls", quic_tls_mod);
    transport_public.addImport("quic_packet", quic_packet_mod);
    transport_public.addImport("config.zig", quic_config_mod);
    transport_public.addImport("loop_backend.zig", loop_backend_mod);
    transport_public.addImport("quic_logger", quic_logger_mod);

    // ========================================================================
    // Phase 14: Integration Test Framework Modules
    // ========================================================================

    // Loopback transport for in-memory testing
    const loopback_mod = mkModule(b, "tests/integration/loopback.zig");
    const testlog_mod = mkModule(b, "tests/helpers/testlog.zig");

    // Loopback transport adapter (adapts loopback to Transport interface)
    const adapter_mod = mkModule(b, "tests/integration/loopback_transport_adapter.zig");
    adapter_mod.addImport("loopback", loopback_mod);
    adapter_mod.addImport("transport", endpoint_transport_mod);
    adapter_mod.addImport("testlog", testlog_mod);

    // Integration test harness (TestEndpoint wrapper with packet capture, time control)
    const integration_harness_mod = mkModule(b, "tests/integration/harness.zig");
    integration_harness_mod.addImport("quic_endpoint", quic_endpoint_mod);
    integration_harness_mod.addImport("quic_conn", quic_conn_mod);
    integration_harness_mod.addImport("quic_config", quic_config_mod);

    // TLS test helpers (shared by scenarios and connection_pair)
    const tls_helpers_mod = mkModule(b, "tests/integration/tls_helpers.zig");

    // Shared Ed25519 test cert/key constants for tests requiring server certificates
    const test_certs_mod = mkModule(b, "tests/helpers/test_ed25519_certs.zig");

    // Endpoint loopback helpers (EndpointWrapper with real Endpoint)
    const endpoint_loopback_helpers_mod = mkModule(b, "tests/integration/endpoint_loopback_helpers.zig");
    endpoint_loopback_helpers_mod.addImport("quic_endpoint", quic_endpoint_mod);
    endpoint_loopback_helpers_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_loopback_helpers_mod.addImport("quic_config", quic_config_mod);
    endpoint_loopback_helpers_mod.addImport("loopback", loopback_mod);
    endpoint_loopback_helpers_mod.addImport("loopback_transport_adapter", adapter_mod);
    endpoint_loopback_helpers_mod.addImport("transport", endpoint_transport_mod);
    endpoint_loopback_helpers_mod.addImport("test_certs", test_certs_mod);

    // ConnectionPair fixture (client-server connection for testing)
    const connection_pair_mod = mkModule(b, "tests/integration/connection_pair.zig");
    connection_pair_mod.addImport("harness", integration_harness_mod);
    connection_pair_mod.addImport("loopback", loopback_mod);
    connection_pair_mod.addImport("endpoint_loopback_helpers", endpoint_loopback_helpers_mod);
    connection_pair_mod.addImport("tls_helpers", tls_helpers_mod);
    connection_pair_mod.addImport("testlog", testlog_mod);

    // Packet inspector (Phase 21.3: packet header parsing and frame extraction for tests)
    const packet_inspector_mod = mkModule(b, "tests/integration/packet_inspector.zig");
    packet_inspector_mod.addImport("harness", integration_harness_mod);
    packet_inspector_mod.addImport("quic_frame", quic_frame_mod);
    packet_inspector_mod.addImport("quic_crypto_quic", quic_crypto_mod);
    packet_inspector_mod.addImport("quic_packet", quic_packet_mod);
    packet_inspector_mod.addImport("quic_tls", quic_tls_mod);
    packet_inspector_mod.addImport("quic_varint", quic_varint_mod);
    packet_inspector_mod.addImport("testlog", testlog_mod);

    // Loss recovery helpers (Phase 21.4: loss detection, RTT estimation, PTO validation for tests)
    const loss_recovery_helpers_mod = mkModule(b, "tests/integration/loss_recovery_helpers.zig");
    loss_recovery_helpers_mod.addImport("harness", integration_harness_mod);
    loss_recovery_helpers_mod.addImport("packet_inspector", packet_inspector_mod);
    loss_recovery_helpers_mod.addImport("testlog", testlog_mod);

    // Advanced features helpers (Phase 21.5: transport params, CID management, Retry, error handling for tests)
    const advanced_features_helpers_mod = mkModule(b, "tests/integration/advanced_features_helpers.zig");
    advanced_features_helpers_mod.addImport("harness", integration_harness_mod);
    advanced_features_helpers_mod.addImport("packet_inspector", packet_inspector_mod);
    advanced_features_helpers_mod.addImport("testlog", testlog_mod);

    // Medium priority helpers (Phase 22: address validation, connection migration, flow control for tests)
    const medium_priority_helpers_mod = mkModule(b, "tests/integration/medium_priority_helpers.zig");
    medium_priority_helpers_mod.addImport("harness", integration_harness_mod);
    medium_priority_helpers_mod.addImport("packet_inspector", packet_inspector_mod);
    medium_priority_helpers_mod.addImport("testlog", testlog_mod);

    // Low priority helpers (Phase 23: key updates, 0-RTT, stress, fault injection, interop for tests)
    const low_priority_helpers_mod = mkModule(b, "tests/integration/low_priority_helpers.zig");
    low_priority_helpers_mod.addImport("harness", integration_harness_mod);
    low_priority_helpers_mod.addImport("packet_inspector", packet_inspector_mod);

    // Scenario builder (fluent API for test setup)
    const scenarios_mod = mkModule(b, "tests/integration/scenarios.zig");
    scenarios_mod.addImport("harness", integration_harness_mod);
    scenarios_mod.addImport("endpoint_loopback_helpers", endpoint_loopback_helpers_mod);
    scenarios_mod.addImport("connection_pair", connection_pair_mod);
    scenarios_mod.addImport("loopback", loopback_mod);
    scenarios_mod.addImport("tls_helpers", tls_helpers_mod);

    const qns_endpoint = addExe(b, "qns-endpoint", "cmd/qns-endpoint.zig", target, optimize);
    qns_endpoint.root_module.addImport("quic_api", quic_api_mod);
    qns_endpoint.root_module.addImport("h3_server", h3_server_mod);
    qns_endpoint.root_module.addImport("h3_client", h3_client_mod);
    const install_qns_endpoint = b.addInstallArtifact(qns_endpoint, .{});

    const cli_step = b.step("cli", "Build QUIC CLI client/server");
    cli_step.dependOn(&install_quic_client.step);
    cli_step.dependOn(&install_quic_client_comprehensive.step);
    cli_step.dependOn(&install_quic_server.step);
    cli_step.dependOn(&install_quic_debug_client.step);
    cli_step.dependOn(&install_quic_debug_dgram_client.step);
    cli_step.dependOn(&install_qns_endpoint.step);

    // Explicit debug clients build step
    const debug_clients = b.step("debug-clients", "Build debug stream/datagram clients");
    debug_clients.dependOn(&install_quic_debug_client.step);
    debug_clients.dependOn(&install_quic_debug_dgram_client.step);

    // Transport layer examples
    const client_transport = addExe(b, "client-transport", "examples/client_transport.zig", target, optimize);
    client_transport.root_module.addImport("quic", transport_public);
    const install_client_transport = b.addInstallArtifact(client_transport, .{});

    const server_transport = addExe(b, "server-transport", "examples/server_transport.zig", target, optimize);
    server_transport.root_module.addImport("quic", transport_public);
    const install_server_transport = b.addInstallArtifact(server_transport, .{});

    const examples_step = b.step("examples", "Build transport layer examples");
    examples_step.dependOn(&install_client_transport.step);
    examples_step.dependOn(&install_server_transport.step);

    // Filtering
    if (filter) |f| {
        if (std.mem.startsWith(u8, f, "transport_geode_compat")) {
            const test_transport_geode_compat_only = addTst(b, testlog_mod, "tests/test_transport_geode_compat.zig", target, optimize);
            test_transport_geode_compat_only.root_module.addImport("transport", transport_public);
            const run_test_transport_geode_compat_only = b.addRunArtifact(test_transport_geode_compat_only);
            test_step.dependOn(&run_test_transport_geode_compat_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "tls_key_schedule_kat")) {
            const test_tls_only = addTst(b, testlog_mod, "tests/test_tls_key_schedule.zig", target, optimize);
            test_tls_only.root_module.addImport("quic_tls", quic_tls_mod);
            const run_test_tls_only = b.addRunArtifact(test_tls_only);
            test_step.dependOn(&run_test_tls_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "timers")) {
            const test_timers_only = addTst(b, testlog_mod, "tests/test_timers.zig", target, optimize);
            test_timers_only.root_module.addImport("quic_api", quic_api_mod);
            test_timers_only.root_module.addImport("quic_conn", quic_conn_mod);
            test_timers_only.root_module.addImport("quic_tls13", tls13_mod);
            const run_test_timers_only = b.addRunArtifact(test_timers_only);
            test_step.dependOn(&run_test_timers_only.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "udp_batch_runtime_smoke")) {
            const test_udp_batch_runtime_smoke = addTst(b, testlog_mod, "src/quic/endpoint/test_udp_batch_runtime_smoke.zig", target, optimize);
            test_udp_batch_runtime_smoke.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_udp_batch_runtime_smoke = b.addRunArtifact(test_udp_batch_runtime_smoke);
            test_step.dependOn(&run_test_udp_batch_runtime_smoke.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "stream_fc") or std.mem.containsAtLeast(u8, f, 1, "streams")) {
            const test_stream_fc = addTst(b, testlog_mod, "tests/test_stream_flow_control.zig", target, optimize);
            test_stream_fc.root_module.addImport("quic_api", quic_api_mod);
            test_stream_fc.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_stream_fc = b.addRunArtifact(test_stream_fc);
            test_step.dependOn(&run_test_stream_fc.step);
            const test_stream_edges = addTst(b, testlog_mod, "tests/test_stream_edge_cases.zig", target, optimize);
            test_stream_edges.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_stream_edges = b.addRunArtifact(test_stream_edges);
            test_step.dependOn(&run_test_stream_edges.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "migration_path") or std.mem.containsAtLeast(u8, f, 1, "path_reset")) {
            const test_migration = addTst(b, testlog_mod, "tests/test_migration_scenarios.zig", target, optimize);
            test_migration.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_migration.root_module.addImport("quic_packet", quic_packet_mod);
            const run_test_migration = b.addRunArtifact(test_migration);
            test_step.dependOn(&run_test_migration.step);
            const test_nat_amp = addTst(b, testlog_mod, "tests/test_nat_rebinding_amplification.zig", target, optimize);
            test_nat_amp.root_module.addImport("quic_endpoint", quic_endpoint_mod);
            test_nat_amp.root_module.addImport("quic_packet", quic_packet_mod);
            const run_test_nat_amp = b.addRunArtifact(test_nat_amp);
            test_step.dependOn(&run_test_nat_amp.step);
            const test_sr = addTst(b, testlog_mod, "tests/test_stateless_reset.zig", target, optimize);
            test_sr.root_module.addImport("quic_conn", quic_conn_mod);
            const run_test_sr = b.addRunArtifact(test_sr);
            test_step.dependOn(&run_test_sr.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "bench_hp")) {
            // No separate test file; run a small subset to validate HP paths quickly
            const test_hp = addTst(b, testlog_mod, "tests/test_hp_sample_offsets.zig", target, optimize);
            test_hp.root_module.addImport("quic_packet", quic_packet_mod);
            const run_test_hp = b.addRunArtifact(test_hp);
            test_step.dependOn(&run_test_hp.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "h3_loopback")) {
            const test_h3_loop = addTst(b, testlog_mod, "tests/test_h3_loopback.zig", target, optimize);
            test_h3_loop.root_module.addImport("quic_api", quic_api_mod);
            test_h3_loop.root_module.addImport("h3_server", h3_server_mod);
            test_h3_loop.root_module.addImport("h3_client", h3_client_mod);
            const run_test_h3_loop = b.addRunArtifact(test_h3_loop);
            test_step.dependOn(&run_test_h3_loop.step);
            return;
        } else if (std.mem.containsAtLeast(u8, f, 1, "public_quic_exports")) {
            const test_public_exports = addTst(b, testlog_mod, "tests/test_public_quic_exports.zig", target, optimize);
            test_public_exports.root_module.addImport("quic", quic_mod);
            const run_test_public_exports = b.addRunArtifact(test_public_exports);
            test_step.dependOn(&run_test_public_exports.step);
            return;
        }
    }

    if (!legacy_tests and (full_test_graph or filter != null)) {
        const test_byteorder = addTst(b, testlog_mod, "tests/test_byteorder.zig", target, optimize);
        test_byteorder.root_module.addImport("byteorder", byteorder_mod);
        const run_test_byteorder = b.addRunArtifact(test_byteorder);
        test_step.dependOn(&run_test_byteorder.step);

        const test_public_exports = addTst(b, testlog_mod, "tests/test_public_quic_exports.zig", target, optimize);
        test_public_exports.root_module.addImport("quic", quic_mod);
        const run_test_public_exports = b.addRunArtifact(test_public_exports);
        test_step.dependOn(&run_test_public_exports.step);

        // mTLS config field tests
        const test_mtls_config = addTst(b, testlog_mod, "tests/test_mtls_config.zig", target, optimize);
        test_mtls_config.root_module.addImport("config", quic_config_mod);
        const run_test_mtls_config = b.addRunArtifact(test_mtls_config);
        test_step.dependOn(&run_test_mtls_config.step);

        // mTLS export verification tests
        const test_mtls_exports = addTst(b, testlog_mod, "tests/test_mtls_exports.zig", target, optimize);
        test_mtls_exports.root_module.addImport("quic", quic_mod);
        const run_test_mtls_exports = b.addRunArtifact(test_mtls_exports);
        test_step.dependOn(&run_test_mtls_exports.step);

        // ========================================================================
        // Phase 1 Unit Tests: Foundation Modules (RFC-based)
        // ========================================================================
        const test_conn_types = addTst(b, testlog_mod, "tests/unit/connection/test_types.zig", target, optimize);
        test_conn_types.root_module.addImport("quic_connection_types", conn_types_mod);
        const run_test_conn_types = b.addRunArtifact(test_conn_types);
        test_step.dependOn(&run_test_conn_types.step);

        const test_frame_streaming = addTst(b, testlog_mod, "tests/test_frame_streaming.zig", target, optimize);
        test_frame_streaming.root_module.addImport("quic_frame", quic_frame_mod);
        test_frame_streaming.root_module.addImport("quic_varint", quic_varint_mod);
        const run_test_frame_streaming = b.addRunArtifact(test_frame_streaming);
        test_step.dependOn(&run_test_frame_streaming.step);

        const test_path_validation = addTst(b, testlog_mod, "tests/test_path_validation.zig", target, optimize);
        test_path_validation.root_module.addImport("quic_api", quic_api_mod);
        test_path_validation.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_path_validation.root_module.addImport("quic_conn", quic_conn_mod);
        test_path_validation.root_module.addImport("quic_packet", quic_packet_mod);
        test_path_validation.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_path_validation = b.addRunArtifact(test_path_validation);
        const test_pv_step = b.step("test-path-validation", "Run path validation tests");
        test_pv_step.dependOn(&run_test_path_validation.step);

        const test_endpoint_types = addTst(b, testlog_mod, "tests/unit/endpoint/test_types.zig", target, optimize);
        test_endpoint_types.root_module.addImport("quic_endpoint_types", endpoint_types_mod);
        test_endpoint_types.root_module.addImport("quic_connection_types", conn_types_mod);
        test_endpoint_types.root_module.addImport("quic_conn", quic_conn_mod);
        const run_test_endpoint_types = b.addRunArtifact(test_endpoint_types);
        test_step.dependOn(&run_test_endpoint_types.step);

        const test_endpoint_timer = addTst(b, testlog_mod, "tests/unit/endpoint/test_timer.zig", target, optimize);
        test_endpoint_timer.root_module.addImport("timer", endpoint_timer_mod);
        test_endpoint_timer.root_module.addImport("types", endpoint_types_mod);
        const run_test_endpoint_timer = b.addRunArtifact(test_endpoint_timer);
        test_step.dependOn(&run_test_endpoint_timer.step);

        const test_endpoint_lookup = addTst(b, testlog_mod, "tests/unit/endpoint/test_lookup.zig", target, optimize);
        test_endpoint_lookup.root_module.addImport("lookup", endpoint_lookup_mod);
        test_endpoint_lookup.root_module.addImport("types", endpoint_types_mod);
        test_endpoint_lookup.root_module.addImport("quic_conn", quic_conn_mod);
        test_endpoint_lookup.root_module.addImport("endpoint/types", endpoint_types_mod);
        test_endpoint_lookup.root_module.addImport("quic_packet", quic_packet_legacy_mod);
        const run_test_endpoint_lookup = b.addRunArtifact(test_endpoint_lookup);
        test_step.dependOn(&run_test_endpoint_lookup.step);

        const test_endpoint_io = addTst(b, testlog_mod, "tests/unit/endpoint/test_io.zig", target, optimize);
        test_endpoint_io.root_module.addImport("io", endpoint_io_mod);
        test_endpoint_io.root_module.addImport("quic_conn", quic_conn_mod);
        const run_test_endpoint_io = b.addRunArtifact(test_endpoint_io);
        test_step.dependOn(&run_test_endpoint_io.step);

        const test_endpoint_client = addTst(b, testlog_mod, "tests/unit/endpoint/test_client.zig", target, optimize);
        test_endpoint_client.root_module.addImport("client", endpoint_client_mod);
        const run_test_endpoint_client = b.addRunArtifact(test_endpoint_client);
        test_step.dependOn(&run_test_endpoint_client.step);

        const test_endpoint_server = addTst(b, testlog_mod, "tests/unit/endpoint/test_server.zig", target, optimize);
        test_endpoint_server.root_module.addImport("server", endpoint_server_mod);
        test_endpoint_server.root_module.addImport("quic_conn", quic_conn_mod);
        test_endpoint_server.root_module.addImport("quic_packet", quic_packet_mod);
        test_endpoint_server.root_module.addImport("quic_token", quic_token_mod);
        test_endpoint_server.root_module.addImport("quic_connection_id", conn_connection_id_mod);
        test_endpoint_server.root_module.addImport("quic_config", quic_config_mod);
        test_endpoint_server.root_module.addImport("endpoint/types", endpoint_types_mod);
        const run_test_endpoint_server = b.addRunArtifact(test_endpoint_server);
        test_step.dependOn(&run_test_endpoint_server.step);

        const test_endpoint_utils = addTst(b, testlog_mod, "tests/unit/endpoint/test_utils.zig", target, optimize);
        test_endpoint_utils.root_module.addImport("utils", endpoint_utils_mod);
        test_endpoint_utils.root_module.addImport("quic_conn", quic_conn_mod);
        const run_test_endpoint_utils = b.addRunArtifact(test_endpoint_utils);
        test_step.dependOn(&run_test_endpoint_utils.step);

        const test_endpoint_incoming = addTst(b, testlog_mod, "tests/unit/endpoint/test_incoming.zig", target, optimize);
        test_endpoint_incoming.root_module.addImport("incoming", endpoint_incoming_mod);
        test_endpoint_incoming.root_module.addImport("endpoint/types", endpoint_types_mod);
        test_endpoint_incoming.root_module.addImport("endpoint/utils", endpoint_utils_mod);
        test_endpoint_incoming.root_module.addImport("quic_conn", quic_conn_mod);
        test_endpoint_incoming.root_module.addImport("config", quic_config_mod);
        test_endpoint_incoming.root_module.addImport("token", quic_token_mod);
        test_endpoint_incoming.root_module.addImport("packet", quic_packet_legacy_mod);
        test_endpoint_incoming.root_module.addImport("varint", quic_varint_mod);
        const run_test_endpoint_incoming = b.addRunArtifact(test_endpoint_incoming);
        test_step.dependOn(&run_test_endpoint_incoming.step);

        const test_incoming_session3 = addTst(b, testlog_mod, "tests/unit/endpoint/test_incoming_session3.zig", target, optimize);
        test_incoming_session3.root_module.addImport("incoming", endpoint_incoming_mod);
        test_incoming_session3.root_module.addImport("endpoint/types", endpoint_types_mod);
        test_incoming_session3.root_module.addImport("endpoint/lookup", endpoint_lookup_mod);
        test_incoming_session3.root_module.addImport("quic_conn", quic_conn_mod);
        test_incoming_session3.root_module.addImport("config", quic_config_mod);
        test_incoming_session3.root_module.addImport("packet", quic_packet_legacy_mod);
        const run_test_incoming_session3 = b.addRunArtifact(test_incoming_session3);
        test_step.dependOn(&run_test_incoming_session3.step);

        const test_endpoint_handshake_integration = addTst(b, testlog_mod, "tests/unit/endpoint/test_handshake_integration.zig", target, optimize);
        test_endpoint_handshake_integration.root_module.addImport("quic_endpoint_handshake_integration", endpoint_handshake_integration_mod);
        test_endpoint_handshake_integration.root_module.addImport("quic_conn", quic_conn_mod);
        test_endpoint_handshake_integration.root_module.addImport("config", quic_config_mod);
        test_endpoint_handshake_integration.root_module.addImport("vendor_ztls_key_schedule", quic_tls_mod);
        test_endpoint_handshake_integration.root_module.addImport("transport_params", quic_transport_params_mod);
        const run_test_endpoint_handshake_integration = b.addRunArtifact(test_endpoint_handshake_integration);
        test_step.dependOn(&run_test_endpoint_handshake_integration.step);

        const test_endpoint_pto = addTst(b, testlog_mod, "tests/unit/endpoint/test_pto.zig", target, optimize);
        test_endpoint_pto.root_module.addImport("pto", endpoint_pto_mod);
        test_endpoint_pto.root_module.addImport("types", endpoint_types_mod);
        const run_test_endpoint_pto = b.addRunArtifact(test_endpoint_pto);
        test_step.dependOn(&run_test_endpoint_pto.step);

        const test_endpoint_frame_handler = addTst(b, testlog_mod, "tests/unit/endpoint/test_frame_handler.zig", target, optimize);
        test_endpoint_frame_handler.root_module.addImport("frame_handler", endpoint_frame_handler_mod);
        test_endpoint_frame_handler.root_module.addImport("frame", quic_frame_mod);
        test_endpoint_frame_handler.root_module.addImport("quic_conn", quic_conn_mod);
        test_endpoint_frame_handler.root_module.addImport("config", quic_config_mod);
        test_endpoint_frame_handler.root_module.addImport("quic_recovery", quic_recovery_mod);
        const run_test_endpoint_frame_handler = b.addRunArtifact(test_endpoint_frame_handler);
        test_step.dependOn(&run_test_endpoint_frame_handler.step);

        const test_packet_number = addTst(b, testlog_mod, "tests/unit/connection/test_packet_number.zig", target, optimize);
        test_packet_number.root_module.addImport("quic_connection_packet_number", conn_packet_number_mod);
        test_packet_number.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_packet_number = b.addRunArtifact(test_packet_number);
        test_step.dependOn(&run_test_packet_number.step);

        // ========================================================================
        // New RFC Compliance Unit Tests
        // ========================================================================

        // Connection module tests
        const test_crypto_buffer = addTst(b, testlog_mod, "tests/unit/connection/test_crypto_buffer.zig", target, optimize);
        test_crypto_buffer.root_module.addImport("crypto_buffer", conn_crypto_buffer_mod);
        const run_test_crypto_buffer = b.addRunArtifact(test_crypto_buffer);
        test_step.dependOn(&run_test_crypto_buffer.step);

        const test_conn_ack = addTst(b, testlog_mod, "tests/unit/connection/test_ack.zig", target, optimize);
        test_conn_ack.root_module.addImport("ack", conn_ack_mod);
        test_conn_ack.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_conn_ack = b.addRunArtifact(test_conn_ack);
        test_step.dependOn(&run_test_conn_ack.step);

        const test_conn_stream = addTst(b, testlog_mod, "tests/unit/connection/test_stream.zig", target, optimize);
        test_conn_stream.root_module.addImport("stream", conn_stream_mod);
        const run_test_conn_stream = b.addRunArtifact(test_conn_stream);
        test_step.dependOn(&run_test_conn_stream.step);

        const test_connection_id_module = addTst(b, testlog_mod, "tests/unit/connection/test_connection_id.zig", target, optimize);
        test_connection_id_module.root_module.addImport("connection_id", conn_connection_id_mod);
        test_connection_id_module.root_module.addImport("types", conn_types_mod);
        const run_test_connection_id_module = b.addRunArtifact(test_connection_id_module);
        test_step.dependOn(&run_test_connection_id_module.step);

        const test_conn_handshake = addTst(b, testlog_mod, "tests/unit/connection/test_handshake.zig", target, optimize);
        test_conn_handshake.root_module.addImport("handshake", conn_handshake_mod);
        const run_test_conn_handshake = b.addRunArtifact(test_conn_handshake);
        test_step.dependOn(&run_test_conn_handshake.step);

        const test_conn_path = addTst(b, testlog_mod, "tests/unit/connection/test_path.zig", target, optimize);
        test_conn_path.root_module.addImport("path", conn_path_mod);
        const run_test_conn_path = b.addRunArtifact(test_conn_path);
        test_step.dependOn(&run_test_conn_path.step);

        const test_conn_amplification = addTst(b, testlog_mod, "tests/unit/connection/test_amplification.zig", target, optimize);
        test_conn_amplification.root_module.addImport("amplification", conn_amplification_mod);
        const run_test_conn_amplification = b.addRunArtifact(test_conn_amplification);
        test_step.dependOn(&run_test_conn_amplification.step);

        const test_conn_pmtud = addTst(b, testlog_mod, "tests/unit/connection/test_pmtud.zig", target, optimize);
        test_conn_pmtud.root_module.addImport("pmtud", conn_pmtud_mod);
        const run_test_conn_pmtud = b.addRunArtifact(test_conn_pmtud);
        test_step.dependOn(&run_test_conn_pmtud.step);

        const test_conn_limits = addTst(b, testlog_mod, "tests/unit/connection/test_limits.zig", target, optimize);
        test_conn_limits.root_module.addImport("limits", conn_limits_mod);
        const run_test_conn_limits = b.addRunArtifact(test_conn_limits);
        test_step.dependOn(&run_test_conn_limits.step);

        const test_conn_flow_control = addTst(b, testlog_mod, "tests/unit/connection/test_flow_control.zig", target, optimize);
        test_conn_flow_control.root_module.addImport("flow_control", conn_flow_control_mod);
        const run_test_conn_flow_control = b.addRunArtifact(test_conn_flow_control);
        test_step.dependOn(&run_test_conn_flow_control.step);

        const test_conn_error = addTst(b, testlog_mod, "tests/unit/connection/test_error.zig", target, optimize);
        test_conn_error.root_module.addImport("error", conn_error_mod);
        const run_test_conn_error = b.addRunArtifact(test_conn_error);
        test_step.dependOn(&run_test_conn_error.step);

        const test_conn_idle = addTst(b, testlog_mod, "tests/unit/connection/test_idle.zig", target, optimize);
        test_conn_idle.root_module.addImport("idle", conn_idle_mod);
        const run_test_conn_idle = b.addRunArtifact(test_conn_idle);
        test_step.dependOn(&run_test_conn_idle.step);

        // Frame module tests
        const test_frame_types = addTst(b, testlog_mod, "tests/unit/frame/test_types.zig", target, optimize);
        test_frame_types.root_module.addImport("types", frame_types_mod);
        const run_test_frame_types = b.addRunArtifact(test_frame_types);
        test_step.dependOn(&run_test_frame_types.step);

        const test_frame_misc = addTst(b, testlog_mod, "tests/unit/frame/test_misc.zig", target, optimize);
        test_frame_misc.root_module.addImport("misc", frame_misc_mod);
        test_frame_misc.root_module.addImport("types", frame_types_mod);
        const run_test_frame_misc = b.addRunArtifact(test_frame_misc);
        test_step.dependOn(&run_test_frame_misc.step);

        const test_frame_crypto = addTst(b, testlog_mod, "tests/unit/frame/test_crypto.zig", target, optimize);
        test_frame_crypto.root_module.addImport("crypto", frame_crypto_mod);
        test_frame_crypto.root_module.addImport("types", frame_types_mod);
        const run_test_frame_crypto = b.addRunArtifact(test_frame_crypto);
        test_step.dependOn(&run_test_frame_crypto.step);

        const test_frame_stream = addTst(b, testlog_mod, "tests/unit/frame/test_stream.zig", target, optimize);
        test_frame_stream.root_module.addImport("stream", frame_stream_mod);
        test_frame_stream.root_module.addImport("types", frame_types_mod);
        const run_test_frame_stream = b.addRunArtifact(test_frame_stream);
        test_step.dependOn(&run_test_frame_stream.step);

        const test_frame_ack = addTst(b, testlog_mod, "tests/unit/frame/test_ack.zig", target, optimize);
        test_frame_ack.root_module.addImport("ack", frame_ack_mod);
        test_frame_ack.root_module.addImport("types", frame_types_mod);
        const run_test_frame_ack = b.addRunArtifact(test_frame_ack);
        test_step.dependOn(&run_test_frame_ack.step);

        const test_frame_path = addTst(b, testlog_mod, "tests/unit/frame/test_path.zig", target, optimize);
        test_frame_path.root_module.addImport("path", frame_path_mod);
        test_frame_path.root_module.addImport("types", frame_types_mod);
        const run_test_frame_path = b.addRunArtifact(test_frame_path);
        test_step.dependOn(&run_test_frame_path.step);

        const test_frame_connection_mgmt = addTst(b, testlog_mod, "tests/unit/frame/test_connection_mgmt.zig", target, optimize);
        test_frame_connection_mgmt.root_module.addImport("connection_mgmt", frame_connection_mgmt_mod);
        test_frame_connection_mgmt.root_module.addImport("types", frame_types_mod);
        const run_test_frame_connection_mgmt = b.addRunArtifact(test_frame_connection_mgmt);
        test_step.dependOn(&run_test_frame_connection_mgmt.step);

        const test_frame_flow_control = addTst(b, testlog_mod, "tests/unit/frame/test_flow_control.zig", target, optimize);
        test_frame_flow_control.root_module.addImport("flow_control", frame_flow_control_mod);
        test_frame_flow_control.root_module.addImport("types", frame_types_mod);
        const run_test_frame_flow_control = b.addRunArtifact(test_frame_flow_control);
        test_step.dependOn(&run_test_frame_flow_control.step);

        const test_frame_datagram = addTst(b, testlog_mod, "tests/unit/frame/test_datagram.zig", target, optimize);
        test_frame_datagram.root_module.addImport("datagram", frame_datagram_mod);
        test_frame_datagram.root_module.addImport("types", frame_types_mod);
        const run_test_frame_datagram = b.addRunArtifact(test_frame_datagram);
        test_step.dependOn(&run_test_frame_datagram.step);

        // Packet module tests
        const test_packet_types = addTst(b, testlog_mod, "tests/unit/packet/test_types.zig", target, optimize);
        test_packet_types.root_module.addImport("types", packet_types_mod);
        const run_test_packet_types = b.addRunArtifact(test_packet_types);
        test_step.dependOn(&run_test_packet_types.step);

        const test_packet_header = addTst(b, testlog_mod, "tests/unit/packet/test_header.zig", target, optimize);
        test_packet_header.root_module.addImport("header", packet_header_mod);
        test_packet_header.root_module.addImport("types", packet_types_mod);
        const run_test_packet_header = b.addRunArtifact(test_packet_header);
        test_step.dependOn(&run_test_packet_header.step);

        const test_packet_packet = addTst(b, testlog_mod, "tests/unit/packet/test_packet.zig", target, optimize);
        test_packet_packet.root_module.addImport("packet", quic_packet_mod);
        const run_test_packet_packet = b.addRunArtifact(test_packet_packet);
        test_step.dependOn(&run_test_packet_packet.step);

        // Version module tests
        const test_version = addTst(b, testlog_mod, "tests/unit/version/test_version.zig", target, optimize);
        test_version.root_module.addImport("version", quic_version_mod);
        const run_test_version = b.addRunArtifact(test_version);
        test_step.dependOn(&run_test_version.step);

        // Recovery module tests
        const test_recovery_types = addTst(b, testlog_mod, "tests/unit/recovery/test_types.zig", target, optimize);
        test_recovery_types.root_module.addImport("types", recovery_types_mod);
        const run_test_recovery_types = b.addRunArtifact(test_recovery_types);
        test_step.dependOn(&run_test_recovery_types.step);

        const test_recovery_rtt = addTst(b, testlog_mod, "tests/unit/recovery/test_rtt.zig", target, optimize);
        test_recovery_rtt.root_module.addImport("rtt", recovery_rtt_mod);
        const run_test_recovery_rtt = b.addRunArtifact(test_recovery_rtt);
        test_step.dependOn(&run_test_recovery_rtt.step);

        const test_recovery_loss_detection = addTst(b, testlog_mod, "tests/unit/recovery/test_loss_detection.zig", target, optimize);
        test_recovery_loss_detection.root_module.addImport("loss_detection", recovery_loss_detection_mod);
        test_recovery_loss_detection.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_recovery_loss_detection = b.addRunArtifact(test_recovery_loss_detection);
        test_step.dependOn(&run_test_recovery_loss_detection.step);

        const test_recovery_congestion = addTst(b, testlog_mod, "tests/unit/recovery/test_congestion.zig", target, optimize);
        test_recovery_congestion.root_module.addImport("congestion", recovery_congestion_mod);
        const run_test_recovery_congestion = b.addRunArtifact(test_recovery_congestion);
        test_step.dependOn(&run_test_recovery_congestion.step);

        const test_recovery_recovery = addTst(b, testlog_mod, "tests/unit/recovery/test_recovery.zig", target, optimize);
        test_recovery_recovery.root_module.addImport("recovery", quic_recovery_mod);
        test_recovery_recovery.root_module.addImport("frame", quic_frame_mod);
        const run_test_recovery_recovery = b.addRunArtifact(test_recovery_recovery);
        test_step.dependOn(&run_test_recovery_recovery.step);

        const test_tls_record = addTst(b, testlog_mod, "tests/test_tls_record_layer.zig", target, optimize);
        test_tls_record.root_module.addImport("tls_record", tls_record_mod);
        const run_test_tls_record = b.addRunArtifact(test_tls_record);
        test_step.dependOn(&run_test_tls_record.step);

        const test_tls_context = addTst(b, testlog_mod, "tests/test_tls_handshake_context.zig", target, optimize);
        test_tls_context.root_module.addImport("quic_tls13", tls13_mod);
        test_tls_context.root_module.addImport("quic_tls", quic_tls_mod);
        test_tls_context.root_module.addImport("quic_transport_params", quic_transport_params_mod);
        test_tls_context.root_module.addImport("test_certs", test_certs_mod);
        const run_test_tls_context = b.addRunArtifact(test_tls_context);
        test_step.dependOn(&run_test_tls_context.step);

        const test_tls_server_flight = addTst(b, testlog_mod, "tests/test_tls_server_handshake_flight.zig", target, optimize);
        test_tls_server_flight.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_tls_server_flight = b.addRunArtifact(test_tls_server_flight);
        test_step.dependOn(&run_test_tls_server_flight.step);

        const test_tls = addTst(b, testlog_mod, "tests/test_tls_key_schedule.zig", target, optimize);
        test_tls.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_tls = b.addRunArtifact(test_tls);
        test_step.dependOn(&run_test_tls.step);

        const test_tls_hs = addTst(b, testlog_mod, "tests/test_tls_handshake_secrets.zig", target, optimize);
        const test_tls_keyupdate = addTst(b, testlog_mod, "tests/test_tls_key_update_exporter.zig", target, optimize);
        test_tls_keyupdate.root_module.addImport("quic_tls13", tls13_mod);
        test_tls_keyupdate.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_tls_keyupdate = b.addRunArtifact(test_tls_keyupdate);
        test_step.dependOn(&run_test_tls_keyupdate.step);
        test_tls_hs.root_module.addImport("quic_tls13", tls13_mod);
        test_tls_hs.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_tls_hs = b.addRunArtifact(test_tls_hs);
        test_step.dependOn(&run_test_tls_hs.step);

        const test_tls_integration = addTst(b, testlog_mod, "tests/test_tls_integration.zig", target, optimize);
        test_tls_integration.root_module.addImport("quic_tls13", tls13_mod);
        test_tls_integration.root_module.addImport("alert", alert_mod);
        test_tls_integration.root_module.addImport("zero_rtt", zero_rtt_mod);
        const run_test_tls_integration = b.addRunArtifact(test_tls_integration);
        test_step.dependOn(&run_test_tls_integration.step);

        const test_initial = addTst(b, testlog_mod, "tests/test_initial_protect.zig", target, optimize);
        test_initial.root_module.addImport("quic_tls", quic_tls_mod);
        test_initial.root_module.addImport("quic_crypto", quic_crypto_mod);
        const run_test_initial = b.addRunArtifact(test_initial);
        test_step.dependOn(&run_test_initial.step);

        const test_rfc_a1 = addTst(b, testlog_mod, "tests/test_rfc9001_a1_initial.zig", target, optimize);
        test_rfc_a1.root_module.addImport("quic_tls", quic_tls_mod);
        test_rfc_a1.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_rfc_a1.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_rfc_a1 = b.addRunArtifact(test_rfc_a1);
        test_step.dependOn(&run_test_rfc_a1.step);

        const test_rfc_a3 = addTst(b, testlog_mod, "tests/test_rfc9001_a3_server_initial.zig", target, optimize);
        test_rfc_a3.root_module.addImport("quic_tls", quic_tls_mod);
        test_rfc_a3.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_rfc_a3.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_rfc_a3 = b.addRunArtifact(test_rfc_a3);
        test_step.dependOn(&run_test_rfc_a3.step);

        const test_crypto_extract = addTst(b, testlog_mod, "tests/test_crypto_extract.zig", target, optimize);
        test_crypto_extract.root_module.addImport("quic_tls", quic_tls_mod);
        test_crypto_extract.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_crypto_extract.root_module.addImport("quic_packet", quic_packet_mod);
        test_crypto_extract.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_crypto_extract = b.addRunArtifact(test_crypto_extract);
        test_step.dependOn(&run_test_crypto_extract.step);

        const test_recovery = addTst(b, testlog_mod, "tests/test_recovery.zig", target, optimize);
        test_recovery.root_module.addImport("quic_recovery", quic_recovery_mod);
        test_recovery.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_recovery = b.addRunArtifact(test_recovery);
        test_step.dependOn(&run_test_recovery.step);

        const test_loop = addTst(b, testlog_mod, "tests/test_initial_handshake_loop.zig", target, optimize);
        test_loop.root_module.addImport("quic_tls", quic_tls_mod);
        test_loop.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_loop.root_module.addImport("quic_packet", quic_packet_mod);
        test_loop.root_module.addImport("quic_frame", quic_frame_mod);
        test_loop.root_module.addImport("quic_tls13", tls13_mod);
        test_loop.root_module.addImport("quic_varint", quic_varint_mod);
        const run_test_loop = b.addRunArtifact(test_loop);
        test_step.dependOn(&run_test_loop.step);

        const test_server_initial = addTst(b, testlog_mod, "tests/test_server_initial_response.zig", target, optimize);
        test_server_initial.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_server_initial.root_module.addImport("quic_conn", quic_conn_mod);
        test_server_initial.root_module.addImport("quic_api", quic_api_mod);
        test_server_initial.root_module.addImport("quic_packet", quic_packet_mod);
        test_server_initial.root_module.addImport("quic_frame", quic_frame_mod);
        test_server_initial.root_module.addImport("quic_varint", quic_varint_mod);
        test_server_initial.root_module.addImport("quic_tls", quic_tls_mod);
        test_server_initial.root_module.addImport("config.zig", quic_config_mod);
        test_server_initial.root_module.addImport("test_certs", test_certs_mod);
        const run_test_server_initial = b.addRunArtifact(test_server_initial);
        test_step.dependOn(&run_test_server_initial.step);

        const test_server_processing = addTst(b, testlog_mod, "tests/test_server_initial_processing.zig", target, optimize);
        test_server_processing.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_server_processing.root_module.addImport("quic_conn", quic_conn_mod);
        test_server_processing.root_module.addImport("quic_packet", quic_packet_mod);
        test_server_processing.root_module.addImport("quic_frame", quic_frame_mod);
        test_server_processing.root_module.addImport("quic_tls", quic_tls_mod);
        test_server_processing.root_module.addImport("config.zig", quic_config_mod);
        const run_test_server_processing = b.addRunArtifact(test_server_processing);
        test_step.dependOn(&run_test_server_processing.step);

        const test_sh = addTst(b, testlog_mod, "tests/test_shortrtt_roundtrip.zig", target, optimize);
        test_sh.root_module.addImport("quic_tls13", tls13_mod);
        test_sh.root_module.addImport("quic_packet", quic_packet_mod);
        test_sh.root_module.addImport("quic_crypto", quic_crypto_mod);
        const run_test_sh = b.addRunArtifact(test_sh);
        test_step.dependOn(&run_test_sh.step);

        // Regression test for RFC 8446 transcript hash handling in 1-RTT key derivation
        const test_transcript = addTst(b, testlog_mod, "tests/test_transcript_hash.zig", target, optimize);
        test_transcript.root_module.addImport("quic_tls13", tls13_mod);
        test_transcript.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_transcript = b.addRunArtifact(test_transcript);
        test_step.dependOn(&run_test_transcript.step);

        const test_pn = addTst(b, testlog_mod, "tests/test_pn_expansion.zig", target, optimize);
        test_pn.root_module.addImport("quic_tls13", tls13_mod);
        test_pn.root_module.addImport("quic_conn", quic_conn_mod);
        const run_test_pn = b.addRunArtifact(test_pn);
        test_step.dependOn(&run_test_pn.step);

        const test_tp = addTst(b, testlog_mod, "tests/test_transport_params.zig", target, optimize);
        test_tp.root_module.addImport("quic_transport_params", quic_transport_params_mod);
        const run_test_tp = b.addRunArtifact(test_tp);
        test_step.dependOn(&run_test_tp.step);

        const test_timers = addTst(b, testlog_mod, "tests/test_timers.zig", target, optimize);
        test_timers.root_module.addImport("quic_api", quic_api_mod);
        test_timers.root_module.addImport("quic_conn", quic_conn_mod);
        test_timers.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_timers = b.addRunArtifact(test_timers);
        test_step.dependOn(&run_test_timers.step);

        const test_vn = addTst(b, testlog_mod, "tests/test_version_negotiation.zig", target, optimize);
        test_vn.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_vn = b.addRunArtifact(test_vn);
        test_step.dependOn(&run_test_vn.step);

        // Zero-length connection ID tests (RFC 9000 §12.2 / TLS Error 266 regression)
        const test_zero_scid = addTst(b, testlog_mod, "tests/test_zero_length_scid_coalescing.zig", target, optimize);
        test_zero_scid.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_zero_scid.root_module.addImport("quic_conn", quic_conn_mod);
        test_zero_scid.root_module.addImport("quic_packet", quic_packet_mod);
        test_zero_scid.root_module.addImport("quic_frame", quic_frame_mod);
        test_zero_scid.root_module.addImport("quic_varint", quic_varint_mod);
        test_zero_scid.root_module.addImport("quic_tls", quic_tls_mod);
        test_zero_scid.root_module.addImport("config.zig", quic_config_mod);
        test_zero_scid.root_module.addImport("test_certs", test_certs_mod);
        const run_test_zero_scid = b.addRunArtifact(test_zero_scid);
        test_step.dependOn(&run_test_zero_scid.step);

        const test_pto_zero_dcid = addTst(b, testlog_mod, "tests/test_pto_probe_zero_length_dcid.zig", target, optimize);
        test_pto_zero_dcid.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_pto_zero_dcid.root_module.addImport("quic_conn", quic_conn_mod);
        test_pto_zero_dcid.root_module.addImport("quic_packet", quic_packet_mod);
        test_pto_zero_dcid.root_module.addImport("quic_frame", quic_frame_mod);
        test_pto_zero_dcid.root_module.addImport("quic_tls", quic_tls_mod);
        test_pto_zero_dcid.root_module.addImport("config.zig", quic_config_mod);
        test_pto_zero_dcid.root_module.addImport("test_certs", test_certs_mod);
        const run_test_pto_zero_dcid = b.addRunArtifact(test_pto_zero_dcid);
        test_step.dependOn(&run_test_pto_zero_dcid.step);

        // New: Retry issuance and amplification gating tests
        const test_retry = addTst(b, testlog_mod, "tests/test_retry.zig", target, optimize);
        test_retry.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_retry.root_module.addImport("quic_packet", quic_packet_mod);
        test_retry.root_module.addImport("quic_varint", quic_varint_mod);
        test_retry.root_module.addImport("quic_tls", quic_tls_mod);
        test_retry.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_retry = b.addRunArtifact(test_retry);
        test_step.dependOn(&run_test_retry.step);

        const test_retry_tamper = addTst(b, testlog_mod, "tests/test_retry_tamper.zig", target, optimize);
        test_retry_tamper.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_retry_tamper.root_module.addImport("quic_packet", quic_packet_mod);
        test_retry_tamper.root_module.addImport("quic_varint", quic_varint_mod);
        test_retry_tamper.root_module.addImport("quic_tls", quic_tls_mod);
        test_retry_tamper.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_retry_tamper = b.addRunArtifact(test_retry_tamper);
        test_step.dependOn(&run_test_retry_tamper.step);

        const test_amp = addTst(b, testlog_mod, "tests/test_amplification.zig", target, optimize);
        test_amp.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_amp.root_module.addImport("quic_packet", quic_packet_mod);
        test_amp.root_module.addImport("quic_varint", quic_varint_mod);
        test_amp.root_module.addImport("quic_tls", quic_tls_mod);
        test_amp.root_module.addImport("quic_frame", quic_frame_mod);
        test_amp.root_module.addImport("quic_crypto", quic_crypto_mod);
        const run_test_amp = b.addRunArtifact(test_amp);
        test_step.dependOn(&run_test_amp.step);

        // ALPN enforcement and getter tests
        const test_alpn = addTst(b, testlog_mod, "tests/test_alpn.zig", target, optimize);
        test_alpn.root_module.addImport("quic_api", quic_api_mod);
        test_alpn.root_module.addImport("quic_conn", quic_conn_mod);
        test_alpn.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_alpn = b.addRunArtifact(test_alpn);
        test_step.dependOn(&run_test_alpn.step);

        const test_conn_metadata = addTst(b, testlog_mod, "tests/test_conn_metadata.zig", target, optimize);
        test_conn_metadata.root_module.addImport("quic_conn", quic_conn_mod);
        test_conn_metadata.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_conn_metadata = b.addRunArtifact(test_conn_metadata);
        test_step.dependOn(&run_test_conn_metadata.step);

        const test_conn_server_name = addTst(b, testlog_mod, "tests/test_connection_server_name.zig", target, optimize);
        test_conn_server_name.root_module.addImport("quic_conn", quic_conn_mod);
        test_conn_server_name.root_module.addImport("quic_tls13", tls13_mod);
        const run_test_conn_server_name = b.addRunArtifact(test_conn_server_name);
        test_step.dependOn(&run_test_conn_server_name.step);

        // Regression test for TLS Error 266 (zero-length SCID in 1-RTT packets)
        const test_zero_scid_1rtt = addTst(b, testlog_mod, "tests/test_zero_length_scid_1rtt.zig", target, optimize);
        test_zero_scid_1rtt.root_module.addImport("quic_api", quic_api_mod);
        test_zero_scid_1rtt.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_zero_scid_1rtt.root_module.addImport("quic_conn", quic_conn_mod);
        test_zero_scid_1rtt.root_module.addImport("quic_packet", quic_packet_mod);
        test_zero_scid_1rtt.root_module.addImport("quic_frame", quic_frame_mod);
        const run_test_zero_scid_1rtt = b.addRunArtifact(test_zero_scid_1rtt);
        test_step.dependOn(&run_test_zero_scid_1rtt.step);

        // TLS SNI negative/allow_insecure tests
        const test_tls_sni = addTst(b, testlog_mod, "tests/test_tls_sni.zig", target, optimize);
        test_tls_sni.root_module.addImport("quic_x509", x509_mod);
        const run_test_tls_sni = b.addRunArtifact(test_tls_sni);
        test_step.dependOn(&run_test_tls_sni.step);

        // TLS validity window KATs
        const test_tls_validity = addTst(b, testlog_mod, "tests/test_tls_validity.zig", target, optimize);
        test_tls_validity.root_module.addImport("quic_x509", x509_mod);
        const run_test_tls_validity = b.addRunArtifact(test_tls_validity);
        test_step.dependOn(&run_test_tls_validity.step);

        // 0-RTT tests
        const test_0rtt = addTst(b, testlog_mod, "tests/test_0rtt.zig", target, optimize);
        test_0rtt.root_module.addImport("quic_packet", quic_packet_mod);
        test_0rtt.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_0rtt.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_0rtt = b.addRunArtifact(test_0rtt);
        test_step.dependOn(&run_test_0rtt.step);

        // Session resumption tests
        const test_resumption = addTst(b, testlog_mod, "tests/test_resumption.zig", target, optimize);
        test_resumption.root_module.addImport("quic_tls13", tls13_mod);
        test_resumption.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_resumption = b.addRunArtifact(test_resumption);
        test_step.dependOn(&run_test_resumption.step);

        // Connection migration tests
        const test_conn_migration = addTst(b, testlog_mod, "tests/test_connection_migration.zig", target, optimize);
        test_conn_migration.root_module.addImport("quic_conn", quic_conn_mod);
        test_conn_migration.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_conn_migration.root_module.addImport("quic_frame", quic_frame_mod);
        test_conn_migration.root_module.addImport("quic_packet", quic_packet_mod);
        const run_test_conn_migration = b.addRunArtifact(test_conn_migration);
        test_step.dependOn(&run_test_conn_migration.step);

        // Preferred address tests
        const test_pref_addr = addTst(b, testlog_mod, "tests/test_preferred_address.zig", target, optimize);
        test_pref_addr.root_module.addImport("quic_transport_params", quic_transport_params_mod);
        const run_test_pref_addr = b.addRunArtifact(test_pref_addr);
        test_step.dependOn(&run_test_pref_addr.step);

        // TLS KU/EKU and malformed DER tests
        const test_kus_ekus = addTst(b, testlog_mod, "tests/test_tls_kus_ekus.zig", target, optimize);
        test_kus_ekus.root_module.addImport("quic_x509", x509_mod);
        const run_test_kus_ekus = b.addRunArtifact(test_kus_ekus);
        test_step.dependOn(&run_test_kus_ekus.step);

        // AEAD/HP KATs
        const test_hp_aead = addTst(b, testlog_mod, "tests/test_hp_aead_kats.zig", target, optimize);
        test_hp_aead.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_hp_aead.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_hp_aead = b.addRunArtifact(test_hp_aead);
        test_step.dependOn(&run_test_hp_aead.step);

        // ECN longitudinal multi-ACK across spaces
        const test_ecn_long = addTst(b, testlog_mod, "tests/test_ecn_longitudinal.zig", target, optimize);
        test_ecn_long.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_ecn_long.root_module.addImport("quic_packet", quic_packet_mod);
        test_ecn_long.root_module.addImport("quic_frame", quic_frame_mod);
        test_ecn_long.root_module.addImport("quic_tls", quic_tls_mod);
        test_ecn_long.root_module.addImport("quic_crypto", quic_crypto_mod);
        test_ecn_long.root_module.addImport("quic_varint", quic_varint_mod);
        const run_test_ecn_long = b.addRunArtifact(test_ecn_long);
        test_step.dependOn(&run_test_ecn_long.step);

        // RX Key Update acceptance tests
        const test_rx_ku = addTst(b, testlog_mod, "tests/test_rx_key_update_accept.zig", target, optimize);
        test_rx_ku.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_rx_ku.root_module.addImport("quic_packet", quic_packet_mod);
        test_rx_ku.root_module.addImport("quic_tls13", tls13_mod);
        test_rx_ku.root_module.addImport("quic_tls", quic_tls_mod);
        const run_test_rx_ku = b.addRunArtifact(test_rx_ku);
        test_step.dependOn(&run_test_rx_ku.step);

        // PMTUD/DPLPMTUD probe sizing + ICMP clamp tests
        const test_pmtud = addTst(b, testlog_mod, "tests/test_pmtud.zig", target, optimize);
        test_pmtud.root_module.addImport("quic_api", quic_api_mod);
        test_pmtud.root_module.addImport("quic_conn", quic_conn_mod);
        test_pmtud.root_module.addImport("quic_packet", quic_packet_mod);
        test_pmtud.root_module.addImport("quic_frame", quic_frame_mod);
        test_pmtud.root_module.addImport("quic_tls13", tls13_mod);
        test_pmtud.root_module.addImport("quic_tls", quic_tls_mod);
        test_pmtud.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        const run_test_pmtud = b.addRunArtifact(test_pmtud);
        test_step.dependOn(&run_test_pmtud.step);

        // ========================================================================
        // Phase 14: Integration Tests (RFC 9000 Tier 1)
        // ========================================================================

        // RFC 9000 Section 7 - Connection Establishment (26 tests)
        const test_rfc9000_section7 = addTst(b, testlog_mod, "tests/integration/rfc9000_section7.zig", target, optimize);
        test_rfc9000_section7.root_module.addImport("scenarios", scenarios_mod);
        test_rfc9000_section7.root_module.addImport("connection_pair", connection_pair_mod);
        test_rfc9000_section7.root_module.addImport("packet_inspector", packet_inspector_mod);
        test_rfc9000_section7.root_module.addImport("quic_transport_params", quic_transport_params_mod);
        // Note: harness is available through scenarios and connection_pair imports
        const run_test_rfc9000_section7 = b.addRunArtifact(test_rfc9000_section7);
        test_step.dependOn(&run_test_rfc9000_section7.step);

        // RFC 9000 Section 8 - Address Validation (Tier 2 Step 4 - 30 tests)
        const test_rfc9000_section8 = addTst(b, testlog_mod, "tests/integration/rfc9000_section8.zig", target, optimize);
        test_rfc9000_section8.root_module.addImport("scenarios", scenarios_mod);
        test_rfc9000_section8.root_module.addImport("connection_pair", connection_pair_mod);
        test_rfc9000_section8.root_module.addImport("harness", integration_harness_mod);
        test_rfc9000_section8.root_module.addImport("loopback", loopback_mod);
        test_rfc9000_section8.root_module.addImport("quic_conn", quic_conn_mod);
        test_rfc9000_section8.root_module.addImport("quic_connection_amplification", conn_amplification_mod);
        const run_test_rfc9000_section8 = b.addRunArtifact(test_rfc9000_section8);
        test_step.dependOn(&run_test_rfc9000_section8.step);

        // RFC 9000 Section 4 - Flow Control (Tier 2 Step 6 - 54 tests)
        const test_flow_control = addTst(b, testlog_mod, "tests/integration/flow_control.zig", target, optimize);
        test_flow_control.root_module.addImport("scenarios", scenarios_mod);
        test_flow_control.root_module.addImport("connection_pair", connection_pair_mod);
        test_flow_control.root_module.addImport("harness", integration_harness_mod);
        test_flow_control.root_module.addImport("loopback", loopback_mod);
        const run_test_flow_control = b.addRunArtifact(test_flow_control);
        test_step.dependOn(&run_test_flow_control.step);

        // RFC 9000 Section 9 - Connection Migration (Tier 2 Step 5 - 46 tests)
        const test_migration = addTst(b, testlog_mod, "tests/integration/migration.zig", target, optimize);
        test_migration.root_module.addImport("scenarios", scenarios_mod);
        test_migration.root_module.addImport("connection_pair", connection_pair_mod);
        test_migration.root_module.addImport("harness", integration_harness_mod);
        test_migration.root_module.addImport("loopback", loopback_mod);
        const run_test_migration = b.addRunArtifact(test_migration);
        test_step.dependOn(&run_test_migration.step);

        // RFC 9000 - Packet Processing Tests (Phase 21.3)
        const test_rfc9000_packets = addTst(b, testlog_mod, "tests/integration/rfc9000_packets.zig", target, optimize);
        test_rfc9000_packets.root_module.addImport("scenarios", scenarios_mod);
        test_rfc9000_packets.root_module.addImport("connection_pair", connection_pair_mod);
        test_rfc9000_packets.root_module.addImport("packet_inspector", packet_inspector_mod);
        test_rfc9000_packets.root_module.addImport("harness", integration_harness_mod);
        test_rfc9000_packets.root_module.addImport("loopback", loopback_mod);
        const run_test_rfc9000_packets = b.addRunArtifact(test_rfc9000_packets);
        test_step.dependOn(&run_test_rfc9000_packets.step);

        // RFC 9002 - Loss Recovery Tests (Phase 21.4)
        const test_rfc9002_recovery = addTst(b, testlog_mod, "tests/integration/rfc9002_recovery.zig", target, optimize);
        test_rfc9002_recovery.root_module.addImport("scenarios", scenarios_mod);
        test_rfc9002_recovery.root_module.addImport("connection_pair", connection_pair_mod);
        test_rfc9002_recovery.root_module.addImport("loss_recovery_helpers", loss_recovery_helpers_mod);
        test_rfc9002_recovery.root_module.addImport("packet_inspector", packet_inspector_mod);
        test_rfc9002_recovery.root_module.addImport("harness", integration_harness_mod);
        test_rfc9002_recovery.root_module.addImport("loopback", loopback_mod);
        const run_test_rfc9002_recovery = b.addRunArtifact(test_rfc9002_recovery);
        test_step.dependOn(&run_test_rfc9002_recovery.step);

        // RFC 9000 - Advanced Features Tests (Phase 21.5)
        const test_rfc9000_advanced = addTst(b, testlog_mod, "tests/integration/rfc9000_advanced.zig", target, optimize);
        test_rfc9000_advanced.root_module.addImport("scenarios", scenarios_mod);
        test_rfc9000_advanced.root_module.addImport("connection_pair", connection_pair_mod);
        test_rfc9000_advanced.root_module.addImport("advanced_features_helpers", advanced_features_helpers_mod);
        test_rfc9000_advanced.root_module.addImport("packet_inspector", packet_inspector_mod);
        test_rfc9000_advanced.root_module.addImport("harness", integration_harness_mod);
        test_rfc9000_advanced.root_module.addImport("loopback", loopback_mod);
        const run_test_rfc9000_advanced = b.addRunArtifact(test_rfc9000_advanced);
        test_step.dependOn(&run_test_rfc9000_advanced.step);

        // RFC 9000 - Medium Priority Features Tests (Phase 22)
        const test_rfc9000_medium = addTst(b, testlog_mod, "tests/integration/rfc9000_medium.zig", target, optimize);
        test_rfc9000_medium.root_module.addImport("scenarios", scenarios_mod);
        test_rfc9000_medium.root_module.addImport("connection_pair", connection_pair_mod);
        test_rfc9000_medium.root_module.addImport("medium_priority_helpers", medium_priority_helpers_mod);
        test_rfc9000_medium.root_module.addImport("packet_inspector", packet_inspector_mod);
        test_rfc9000_medium.root_module.addImport("harness", integration_harness_mod);
        test_rfc9000_medium.root_module.addImport("loopback", loopback_mod);
        const run_test_rfc9000_medium = b.addRunArtifact(test_rfc9000_medium);
        test_step.dependOn(&run_test_rfc9000_medium.step);

        // RFC 9001 - Advanced TLS Features Tests (Phase 23)
        const test_rfc9001_advanced = addTst(b, testlog_mod, "tests/integration/rfc9001_advanced.zig", target, optimize);
        test_rfc9001_advanced.root_module.addImport("scenarios", scenarios_mod);
        test_rfc9001_advanced.root_module.addImport("connection_pair", connection_pair_mod);
        test_rfc9001_advanced.root_module.addImport("low_priority_helpers", low_priority_helpers_mod);
        test_rfc9001_advanced.root_module.addImport("packet_inspector", packet_inspector_mod);
        test_rfc9001_advanced.root_module.addImport("harness", integration_harness_mod);
        test_rfc9001_advanced.root_module.addImport("loopback", loopback_mod);
        const run_test_rfc9001_advanced = b.addRunArtifact(test_rfc9001_advanced);
        test_step.dependOn(&run_test_rfc9001_advanced.step);

        // RFC 9001 §6 - Key Update Tests (Tier 3 Step 7 - 61 tests)
        const test_key_update = addTst(b, testlog_mod, "tests/integration/key_update.zig", target, optimize);
        test_key_update.root_module.addImport("scenarios", scenarios_mod);
        test_key_update.root_module.addImport("connection_pair", connection_pair_mod);
        test_key_update.root_module.addImport("harness", integration_harness_mod);
        test_key_update.root_module.addImport("loopback", loopback_mod);
        const run_test_key_update = b.addRunArtifact(test_key_update);
        test_step.dependOn(&run_test_key_update.step);

        // RFC 9001 §4.6 - 0-RTT and Session Resumption Tests (Tier 3 Step 8 - 72 tests)
        const test_zero_rtt = addTst(b, testlog_mod, "tests/integration/zero_rtt.zig", target, optimize);
        test_zero_rtt.root_module.addImport("scenarios", scenarios_mod);
        test_zero_rtt.root_module.addImport("connection_pair", connection_pair_mod);
        test_zero_rtt.root_module.addImport("harness", integration_harness_mod);
        test_zero_rtt.root_module.addImport("loopback", loopback_mod);
        const run_test_zero_rtt = b.addRunArtifact(test_zero_rtt);
        test_step.dependOn(&run_test_zero_rtt.step);

        // Stress and Performance Tests (Tier 3 Step 9 - 46 tests)
        const test_stress = addTst(b, testlog_mod, "tests/integration/stress/stress.zig", target, optimize);
        test_stress.root_module.addImport("scenarios", scenarios_mod);
        test_stress.root_module.addImport("connection_pair", connection_pair_mod);
        test_stress.root_module.addImport("harness", integration_harness_mod);
        const run_test_stress = b.addRunArtifact(test_stress);
        test_step.dependOn(&run_test_stress.step);

        // Fault Injection Tests (Tier 3 Step 9 - 62 tests)
        const test_fault = addTst(b, testlog_mod, "tests/integration/fault/fault.zig", target, optimize);
        test_fault.root_module.addImport("scenarios", scenarios_mod);
        test_fault.root_module.addImport("connection_pair", connection_pair_mod);
        test_fault.root_module.addImport("harness", integration_harness_mod);
        test_fault.root_module.addImport("loopback", loopback_mod);
        const run_test_fault = b.addRunArtifact(test_fault);
        test_step.dependOn(&run_test_fault.step);

        // Interoperability Tests (Tier 3 Step 10 - 48 tests)
        const test_interop = addTst(b, testlog_mod, "tests/integration/interop/interop.zig", target, optimize);
        test_interop.root_module.addImport("scenarios", scenarios_mod);
        test_interop.root_module.addImport("harness", integration_harness_mod);
        const run_test_interop = b.addRunArtifact(test_interop);
        test_step.dependOn(&run_test_interop.step);

        // CI/CD Helpers Unit Tests (Phase 24)
        const test_ci_helpers = addTst(b, testlog_mod, "tests/integration/ci_helpers.zig", target, optimize);
        const run_test_ci_helpers = b.addRunArtifact(test_ci_helpers);
        test_step.dependOn(&run_test_ci_helpers.step);

        // GAP-0200: Thread-Safety Unit Tests
        const test_thread_safety = addTst(b, testlog_mod, "tests/test_thread_safety.zig", target, optimize);
        test_thread_safety.root_module.addImport("quic", quic_api_mod);
        test_thread_safety.root_module.addImport("quic_endpoint", quic_endpoint_mod);
        test_thread_safety.root_module.addImport("quic_conn", quic_conn_mod);
        test_thread_safety.root_module.addImport("quic_config", quic_config_mod);
        const run_test_thread_safety = b.addRunArtifact(test_thread_safety);
        test_step.dependOn(&run_test_thread_safety.step);

        // Geode transport-compat coverage for high-level transport API parity.
        const test_transport_geode_compat = addTst(b, testlog_mod, "tests/test_transport_geode_compat.zig", target, optimize);
        test_transport_geode_compat.root_module.addImport("transport", transport_public);
        const run_test_transport_geode_compat = b.addRunArtifact(test_transport_geode_compat);
        test_step.dependOn(&run_test_transport_geode_compat.step);
    } else if (!legacy_tests) {
        // Fast default graph: grouped smoke suite keeps `zig build test` responsive.
        // Use `zig build -Dfull-test-graph=true test` for full per-file coverage.
        const test_smoke = addTst(b, testlog_mod, "tests/smoke.zig", target, optimize);
        test_smoke.root_module.addImport("quic", quic_mod);
        test_smoke.root_module.addImport("transport", transport_public);
        test_smoke.root_module.addImport("byteorder", byteorder_mod);
        test_smoke.root_module.addImport("version", quic_version_mod);
        const run_test_smoke = b.addRunArtifact(test_smoke);
        test_step.dependOn(&run_test_smoke.step);
    } else {
        const test_quic = addTst(b, testlog_mod, "quic.zig", target, optimize);
        const run_test_quic = b.addRunArtifact(test_quic);
        test_step.dependOn(&run_test_quic.step);
    }

    // Fuzzers
    const fuzz_varint = addExe(b, "fuzz_varint", "fuzz/fuzz_varint.zig", target, optimize);
    const fuzz_frame = addExe(b, "fuzz_frame_parse", "fuzz/fuzz_frame_parse.zig", target, optimize);
    const fuzz_vn = addExe(b, "fuzz_vn_parse", "fuzz/fuzz_vn_parse.zig", target, optimize);
    const fuzz_short = addExe(b, "fuzz_short_decode", "fuzz/fuzz_short_decode.zig", target, optimize);
    const fuzz_tls_hello = addExe(b, "fuzz_tls_hello", "fuzz/fuzz_tls_hello.zig", target, optimize);
    const fuzz_tls_cert = addExe(b, "fuzz_tls_cert", "fuzz/fuzz_tls_cert.zig", target, optimize);
    fuzz_varint.root_module.addImport("quic_varint", quic_varint_mod);
    fuzz_frame.root_module.addImport("quic_frame", quic_frame_mod);
    fuzz_frame.root_module.addImport("quic_varint", quic_varint_mod);
    fuzz_vn.root_module.addImport("quic_packet", quic_packet_mod);
    fuzz_short.root_module.addImport("quic_packet", quic_packet_mod);
    const install_fuzz_varint = b.addInstallArtifact(fuzz_varint, .{});
    const install_fuzz_frame = b.addInstallArtifact(fuzz_frame, .{});
    const install_fuzz_vn = b.addInstallArtifact(fuzz_vn, .{});
    const install_fuzz_short = b.addInstallArtifact(fuzz_short, .{});
    const install_fuzz_tls_hello = b.addInstallArtifact(fuzz_tls_hello, .{});
    const install_fuzz_tls_cert = b.addInstallArtifact(fuzz_tls_cert, .{});
    const fuzz_step = b.step("fuzz", "Build fuzzers");
    fuzz_step.dependOn(&install_fuzz_varint.step);
    fuzz_step.dependOn(&install_fuzz_frame.step);
    fuzz_step.dependOn(&install_fuzz_vn.step);
    fuzz_step.dependOn(&install_fuzz_short.step);
    fuzz_step.dependOn(&install_fuzz_tls_hello.step);
    fuzz_step.dependOn(&install_fuzz_tls_cert.step);

    // Benchmarks
    const bench = addExe(b, "quic-bench", "bench/main.zig", target, optimize);
    bench.root_module.addImport("quic_varint", quic_varint_mod);
    bench.root_module.addImport("quic_recovery", quic_recovery_mod);
    bench.root_module.addImport("quic_packet", quic_packet_mod);
    bench.root_module.addImport("quic_crypto", quic_crypto_mod);
    bench.root_module.addImport("quic_tls", quic_tls_mod);
    const install_bench = b.addInstallArtifact(bench, .{});
    const run_bench = b.addRunArtifact(bench);
    const bench_step = b.step("bench", "Run benchmark gate and build benchmark binaries");
    bench_step.dependOn(&install_bench.step);
    bench_step.dependOn(&run_bench.step);

    // TLS benchmarks
    const bench_tls_hs = addExe(b, "bench_tls_handshake", "bench/bench_tls_handshake.zig", target, .ReleaseFast);
    bench_tls_hs.root_module.addImport("quic_tls13", tls13_mod);
    bench_tls_hs.root_module.addImport("quic_tls", quic_tls_mod);
    const install_bench_tls_hs = b.addInstallArtifact(bench_tls_hs, .{});
    bench_step.dependOn(&install_bench_tls_hs.step);

    const bench_tls_aead = addExe(b, "bench_tls_aead", "bench/bench_tls_aead.zig", target, .ReleaseFast);
    const install_bench_tls_aead = b.addInstallArtifact(bench_tls_aead, .{});
    bench_step.dependOn(&install_bench_tls_aead.step);
}
