// Helper for setting up the QUIC library as a vendor dependency
//
// Usage in your build.zig:
// ```zig
// const quic_vendor_setup = @import("vendor/quic/vendor_setup.zig");
//
// pub fn build(b: *std.Build) void {
//     const target = b.standardTargetOptions(.{});
//     const optimize = b.standardOptimizeOption(.{});
//
//     // Setup QUIC modules
//     const quic_modules = quic_vendor_setup.setupModules(b, "vendor/quic", target, optimize);
//
//     // Add to your exe/lib
//     exe.root_module.addImport("quic", quic_modules.quic_api);
//     exe.root_module.addImport("quic_endpoint", quic_modules.quic_endpoint);
//     exe.root_module.addImport("quic_conn", quic_modules.quic_conn);
//     // ... add other modules as needed
// }
// ```

const std = @import("std");

pub const QuicModules = struct {
    byteorder: *std.Build.Module,
    quic_api: *std.Build.Module,
    quic_endpoint: *std.Build.Module,
    quic_conn: *std.Build.Module,
    quic_packet: *std.Build.Module,
    quic_frame: *std.Build.Module,
    quic_varint: *std.Build.Module,
    quic_tls: *std.Build.Module,
    quic_tls13: *std.Build.Module,
    quic_crypto: *std.Build.Module,
    quic_recovery: *std.Build.Module,
    quic_transport_params: *std.Build.Module,
    quic_logger: *std.Build.Module,
    config: *std.Build.Module,
    loop_backend: *std.Build.Module,
    asn1: *std.Build.Module,
    sig: *std.Build.Module,
    x509: *std.Build.Module,
    token: *std.Build.Module,
};

pub fn setupModules(
    b: *std.Build,
    quic_path: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) QuicModules {
    _ = target;
    _ = optimize;

    const mkModule = struct {
        fn mk(builder: *std.Build, root_path: []const u8, sub_path: []const u8) *std.Build.Module {
            const full_path = builder.pathJoin(&.{ root_path, sub_path });
            return builder.addModule("mod", .{
                .root_source_file = builder.path(full_path),
            });
        }
    }.mk;

    // Core byteorder module - REQUIRED by multiple QUIC modules
    const byteorder_mod = mkModule(b, quic_path, "src/byteorder/byteorder.zig");

    // TLS/crypto modules - ztls is vendored inside vendor/quic/vendor/ztls
    const ztls_path = b.pathJoin(&.{ quic_path, "vendor/ztls" });
    const quic_tls_mod = mkModule(b, ztls_path, "src/key_schedule.zig");
    const quic_crypto_mod = mkModule(b, quic_path, "src/quic/crypto_quic.zig");
    const asn1_mod = mkModule(b, ztls_path, "src/asn1.zig");
    const sig_mod = mkModule(b, ztls_path, "src/sig.zig");
    const x509_mod = mkModule(b, ztls_path, "src/x509.zig");
    const sct_mod = mkModule(b, ztls_path, "src/sct.zig");
    const zero_rtt_mod = mkModule(b, ztls_path, "src/zero_rtt.zig");
    const quic_tls13_mod = mkModule(b, ztls_path, "src/tls13.zig");
    const tls13_full_mod = mkModule(b, ztls_path, "src/tls13_full.zig");

    // Core QUIC modules
    const quic_logger_mod = mkModule(b, quic_path, "src/quic/logger.zig");
    const config_mod = mkModule(b, quic_path, "src/quic/config.zig");
    const loop_backend_mod = mkModule(b, quic_path, "src/quic/loop_backend.zig");
    const token_mod = mkModule(b, quic_path, "src/quic/token.zig");

    // Varint
    const quic_varint_mod = mkModule(b, quic_path, "src/quic/varint.zig");
    quic_varint_mod.addImport("byteorder", byteorder_mod);

    // Frame submodules (modular structure from vendor/quic/build.zig)
    const frame_types_mod = mkModule(b, quic_path, "src/quic/frame/types.zig");
    const frame_misc_mod = mkModule(b, quic_path, "src/quic/frame/misc.zig");
    frame_misc_mod.addImport("types", frame_types_mod);
    frame_misc_mod.addImport("quic_varint", quic_varint_mod);
    const frame_crypto_mod = mkModule(b, quic_path, "src/quic/frame/crypto.zig");
    frame_crypto_mod.addImport("types", frame_types_mod);
    frame_crypto_mod.addImport("quic_varint", quic_varint_mod);
    const frame_stream_mod = mkModule(b, quic_path, "src/quic/frame/stream.zig");
    frame_stream_mod.addImport("types", frame_types_mod);
    frame_stream_mod.addImport("quic_varint", quic_varint_mod);
    const frame_ack_mod = mkModule(b, quic_path, "src/quic/frame/ack.zig");
    frame_ack_mod.addImport("types", frame_types_mod);
    frame_ack_mod.addImport("quic_varint", quic_varint_mod);
    const frame_path_mod = mkModule(b, quic_path, "src/quic/frame/path.zig");
    frame_path_mod.addImport("types", frame_types_mod);
    const frame_connection_mgmt_mod = mkModule(b, quic_path, "src/quic/frame/connection_mgmt.zig");
    frame_connection_mgmt_mod.addImport("types", frame_types_mod);
    frame_connection_mgmt_mod.addImport("quic_varint", quic_varint_mod);
    const frame_flow_control_mod = mkModule(b, quic_path, "src/quic/frame/flow_control.zig");
    frame_flow_control_mod.addImport("types", frame_types_mod);
    frame_flow_control_mod.addImport("quic_varint", quic_varint_mod);
    const frame_datagram_mod = mkModule(b, quic_path, "src/quic/frame/datagram.zig");
    frame_datagram_mod.addImport("types", frame_types_mod);
    frame_datagram_mod.addImport("quic_varint", quic_varint_mod);

    // Frame coordinator module (exports NewConnectionId and other frame types)
    const quic_frame_mod = mkModule(b, quic_path, "src/quic/frame/frame.zig");
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

    // Transport parameters
    const quic_transport_params_mod = mkModule(b, quic_path, "src/quic/transport_params.zig");
    quic_transport_params_mod.addImport("quic_varint", quic_varint_mod);

    // Packet module
    const quic_packet_mod = mkModule(b, quic_path, "src/quic/packet.zig");
    quic_packet_mod.addImport("quic_tls", quic_tls_mod);
    quic_packet_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_packet_mod.addImport("quic_varint", quic_varint_mod);
    quic_packet_mod.addImport("quic_logger", quic_logger_mod);

    // Recovery module
    const quic_recovery_mod = mkModule(b, quic_path, "src/quic/recovery.zig");
    quic_recovery_mod.addImport("quic_frame", quic_frame_mod);

    // Connection module
    const quic_conn_mod = mkModule(b, quic_path, "src/quic/conn.zig");
    quic_conn_mod.addImport("quic_tls13", quic_tls13_mod);
    quic_conn_mod.addImport("quic_packet", quic_packet_mod);
    quic_conn_mod.addImport("quic_frame", quic_frame_mod);
    quic_conn_mod.addImport("quic_recovery", quic_recovery_mod);
    quic_conn_mod.addImport("quic_tls", quic_tls_mod);
    quic_conn_mod.addImport("quic_transport_params", quic_transport_params_mod);
    quic_conn_mod.addImport("quic_logger", quic_logger_mod);
    quic_conn_mod.addImport("byteorder", byteorder_mod);  // IMPORTANT: conn.zig needs byteorder

    // Endpoint submodules (following vendor/quic/build.zig pattern)
    const endpoint_types_mod = mkModule(b, quic_path, "src/quic/endpoint/types.zig");
    endpoint_types_mod.addImport("quic_conn", quic_conn_mod);

    const endpoint_lookup_mod = mkModule(b, quic_path, "src/quic/endpoint/lookup.zig");
    endpoint_lookup_mod.addImport("types", endpoint_types_mod);
    endpoint_lookup_mod.addImport("quic_conn", quic_conn_mod);

    const endpoint_handshake_integration_mod = mkModule(b, quic_path, "src/quic/endpoint/handshake_integration.zig");
    endpoint_handshake_integration_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_handshake_integration_mod.addImport("packet", quic_packet_mod);
    endpoint_handshake_integration_mod.addImport("frame", quic_frame_mod);
    endpoint_handshake_integration_mod.addImport("crypto_quic", quic_crypto_mod);
    endpoint_handshake_integration_mod.addImport("transport_params", quic_transport_params_mod);
    endpoint_handshake_integration_mod.addImport("vendor_ztls_tls13", quic_tls13_mod);
    endpoint_handshake_integration_mod.addImport("vendor_ztls_key_schedule", quic_tls_mod);
    endpoint_handshake_integration_mod.addImport("config", config_mod);

    const endpoint_frame_handler_mod = mkModule(b, quic_path, "src/quic/endpoint/frame_handler.zig");
    endpoint_frame_handler_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_frame_handler_mod.addImport("frame", quic_frame_mod);
    endpoint_frame_handler_mod.addImport("packet", quic_packet_mod);
    endpoint_frame_handler_mod.addImport("config", config_mod);

    const endpoint_client_mod = mkModule(b, quic_path, "src/quic/endpoint/client.zig");
    endpoint_client_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_client_mod.addImport("quic_packet", quic_packet_mod);
    endpoint_client_mod.addImport("quic_frame", quic_frame_mod);
    endpoint_client_mod.addImport("quic_tls", quic_tls_mod);
    endpoint_client_mod.addImport("types", endpoint_types_mod);
    endpoint_client_mod.addImport("handshake_integration", endpoint_handshake_integration_mod);
    endpoint_client_mod.addImport("quic_tls13", quic_tls13_mod);

    const endpoint_server_mod = mkModule(b, quic_path, "src/quic/endpoint/server.zig");
    endpoint_server_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_server_mod.addImport("types", endpoint_types_mod);
    endpoint_server_mod.addImport("config", config_mod);
    endpoint_server_mod.addImport("transport_params", quic_transport_params_mod);
    endpoint_server_mod.addImport("packet", quic_packet_mod);
    endpoint_server_mod.addImport("x509", x509_mod);
    endpoint_server_mod.addImport("sig", sig_mod);

    const endpoint_incoming_mod = mkModule(b, quic_path, "src/quic/endpoint/incoming.zig");
    endpoint_incoming_mod.addImport("quic_conn", quic_conn_mod);
    endpoint_incoming_mod.addImport("packet", quic_packet_mod);
    endpoint_incoming_mod.addImport("types", endpoint_types_mod);
    endpoint_incoming_mod.addImport("vendor_ztls_key_schedule", quic_tls_mod);
    endpoint_incoming_mod.addImport("crypto_quic", quic_crypto_mod);
    endpoint_incoming_mod.addImport("frame", quic_frame_mod);
    endpoint_incoming_mod.addImport("varint", quic_varint_mod);
    endpoint_incoming_mod.addImport("transport_params", quic_transport_params_mod);
    endpoint_incoming_mod.addImport("token", token_mod);
    endpoint_incoming_mod.addImport("x509", x509_mod);
    endpoint_incoming_mod.addImport("sig", sig_mod);
    endpoint_incoming_mod.addImport("lookup", endpoint_lookup_mod);
    endpoint_incoming_mod.addImport("config", config_mod);
    endpoint_incoming_mod.addImport("frame_handler", endpoint_frame_handler_mod);
    endpoint_incoming_mod.addImport("handshake_integration", endpoint_handshake_integration_mod);

    // Main endpoint module with submodule imports using relative paths
    const quic_endpoint_mod = mkModule(b, quic_path, "src/quic/endpoint.zig");
    quic_endpoint_mod.addImport("types", endpoint_types_mod);
    quic_endpoint_mod.addImport("config", config_mod);
    quic_endpoint_mod.addImport("config.zig", config_mod);
    quic_endpoint_mod.addImport("loop_backend.zig", loop_backend_mod);
    quic_endpoint_mod.addImport("quic_conn", quic_conn_mod);
    quic_endpoint_mod.addImport("quic_packet", quic_packet_mod);
    quic_endpoint_mod.addImport("quic_frame", quic_frame_mod);
    quic_endpoint_mod.addImport("quic_tls", quic_tls_mod);
    quic_endpoint_mod.addImport("quic_tls13", quic_tls13_mod);
    quic_endpoint_mod.addImport("sig", sig_mod);
    quic_endpoint_mod.addImport("x509", x509_mod);
    quic_endpoint_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_endpoint_mod.addImport("quic_varint", quic_varint_mod);
    quic_endpoint_mod.addImport("token.zig", token_mod);
    quic_endpoint_mod.addImport("quic_recovery", quic_recovery_mod);
    quic_endpoint_mod.addImport("quic_transport_params", quic_transport_params_mod);
    quic_endpoint_mod.addImport("quic_logger", quic_logger_mod);
    quic_endpoint_mod.addImport("byteorder", byteorder_mod);
    // Add endpoint submodules via relative paths (for endpoint.zig to import them)
    quic_endpoint_mod.addImport("endpoint/lookup.zig", endpoint_lookup_mod);
    quic_endpoint_mod.addImport("endpoint/handshake_integration.zig", endpoint_handshake_integration_mod);
    quic_endpoint_mod.addImport("endpoint/frame_handler.zig", endpoint_frame_handler_mod);
    quic_endpoint_mod.addImport("endpoint/incoming.zig", endpoint_incoming_mod);
    quic_endpoint_mod.addImport("endpoint/client.zig", endpoint_client_mod);
    quic_endpoint_mod.addImport("endpoint/server.zig", endpoint_server_mod);

    // TLS13 module dependencies
    quic_tls13_mod.addImport("tls13_full", tls13_full_mod);
    quic_tls13_mod.addImport("sct", sct_mod);
    quic_tls13_mod.addImport("zero_rtt", zero_rtt_mod);
    quic_tls13_mod.addImport("quic_tls", quic_tls_mod);
    quic_tls13_mod.addImport("asn1", asn1_mod);
    quic_tls13_mod.addImport("sig", sig_mod);
    quic_tls13_mod.addImport("x509", x509_mod);
    quic_tls13_mod.addImport("quic_logger", quic_logger_mod);

    // Signature module dependencies
    sig_mod.addImport("asn1", asn1_mod);

    // X509 module dependencies
    x509_mod.addImport("asn1", asn1_mod);
    x509_mod.addImport("sig", sig_mod);

    // Crypto module dependencies
    quic_crypto_mod.addImport("quic_logger", quic_logger_mod);
    quic_crypto_mod.addImport("quic_tls", quic_tls_mod);

    // Token module dependencies
    token_mod.addImport("byteorder", byteorder_mod);  // IMPORTANT: token.zig needs byteorder

    // API module (main entry point)
    const quic_api_mod = mkModule(b, quic_path, "src/quic/api.zig");
    quic_api_mod.addImport("config.zig", config_mod);
    quic_api_mod.addImport("loop_backend.zig", loop_backend_mod);
    quic_api_mod.addImport("quic_conn", quic_conn_mod);
    quic_api_mod.addImport("quic_endpoint", quic_endpoint_mod);
    quic_api_mod.addImport("quic_packet", quic_packet_mod);
    quic_api_mod.addImport("quic_frame", quic_frame_mod);
    quic_api_mod.addImport("quic_tls", quic_tls_mod);
    quic_api_mod.addImport("quic_tls13", quic_tls13_mod);
    quic_api_mod.addImport("quic_crypto", quic_crypto_mod);
    quic_api_mod.addImport("quic_varint", quic_varint_mod);
    quic_api_mod.addImport("quic_recovery", quic_recovery_mod);
    quic_api_mod.addImport("quic_transport_params", quic_transport_params_mod);
    quic_api_mod.addImport("quic_logger", quic_logger_mod);
    quic_api_mod.addImport("byteorder", byteorder_mod);
    quic_api_mod.addImport("token.zig", token_mod);
    quic_api_mod.addImport("asn1", asn1_mod);
    quic_api_mod.addImport("sig", sig_mod);
    quic_api_mod.addImport("x509", x509_mod);

    return .{
        .byteorder = byteorder_mod,
        .quic_api = quic_api_mod,
        .quic_endpoint = quic_endpoint_mod,
        .quic_conn = quic_conn_mod,
        .quic_packet = quic_packet_mod,
        .quic_frame = quic_frame_mod,
        .quic_varint = quic_varint_mod,
        .quic_tls = quic_tls_mod,
        .quic_tls13 = quic_tls13_mod,
        .quic_crypto = quic_crypto_mod,
        .quic_recovery = quic_recovery_mod,
        .quic_transport_params = quic_transport_params_mod,
        .quic_logger = quic_logger_mod,
        .config = config_mod,
        .loop_backend = loop_backend_mod,
        .asn1 = asn1_mod,
        .sig = sig_mod,
        .x509 = x509_mod,
        .token = token_mod,
    };
}