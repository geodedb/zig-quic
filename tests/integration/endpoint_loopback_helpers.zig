//! Endpoint-Loopback Integration Helpers
//!
//! This module provides helper utilities for testing the production QUIC endpoint
//! with loopback transport. These helpers make it easy to enable the 474 skip tests
//! by abstracting common patterns for endpoint creation, connection establishment,
//! and test scenarios.
//!
//! ## Purpose
//!
//! With Phase 8 (a/b/c) complete, the production endpoint now uses the Transport
//! abstraction. This enables deterministic testing using LoopbackTransport instead
//! of real UDP sockets. These helpers bridge the gap between the test framework
//! (Phases 1-7) and the production endpoint.
//!
//! ## Phase 14 Status: Production Endpoint Integration Capability Demonstrated
//!
//! Phase 14 validates that the production Endpoint CAN be created with the loopback
//! adapter via Endpoint.initWithTransport(). However, full TLS handshake testing is
//! deferred to Phase 15+ due to complexity:
//!
//! **What Phase 14 Achieves:**
//! - ✅ Demonstrates Endpoint.initWithTransport() works with LoopbackTransportAdapter
//! - ✅ Shows minimal QuicConfig setup required for endpoint creation
//! - ✅ Validates adapter provides compatible Transport interface
//! - ✅ Confirms architectural integration (adapter → Transport → Endpoint)
//!
//! **What's Deferred to Phase 15+:**
//! - 📝 TLS certificate generation/management infrastructure
//! - 📝 Complete TLS handshake state machine integration
//! - 📝 CRYPTO frame handling over loopback
//! - 📝 Connection establishment and lifecycle management
//! - 📝 Full RFC 9000 §7 compliance tests (Initial/Handshake packets)
//!
//! **Design Decision Rationale:**
//! Taking an incremental approach avoids scope creep. Phase 14 proves the architectural
//! integration works, while complex TLS setup is a separate concern best handled in
//! dedicated phases. The EndpointWrapper pattern continues to serve integration tests
//! effectively while real endpoint capability is demonstrated separately.
//!
//! ## Usage Pattern
//!
//! ```zig
//! test "RFC 9000 §7 - Basic handshake" {
//!     var helper = try EndpointLoopbackHelper.init(testing.allocator);
//!     defer helper.deinit();
//!
//!     // Configure loopback with fault injection
//!     helper.loopback_config.loss_rate = 0.05;  // 5% packet loss
//!
//!     // Create client and server endpoints
//!     var client = try helper.createClientEndpoint();
//!     var server = try helper.createServerEndpoint();
//!
//!     // Establish connection
//!     var conn = try helper.connectClientToServer(client, server);
//!
//!     // Wait for handshake
//!     try helper.waitForHandshake(conn, 5000); // 5 second timeout
//!
//!     // Test assertions
//!     try testing.expect(conn.isHandshakeComplete());
//! }
//! ```
//!
//! ## Production Endpoint Integration (Phase 14 example)
//!
//! When TLS infrastructure is ready, production endpoints can be created as follows:
//!
//! ```zig
//! // Create minimal config
//! const quic_config = QuicConfig{
//!     .alpn = &[_][]const u8{"test"},  // Only required field
//!     .allow_insecure = true,          // For testing only
//! };
//!
//! // Create adapter
//! var adapter = LoopbackTransportAdapter.init(loopback_transport, .SideA);
//!
//! // Create real endpoint with loopback adapter
//! var endpoint = try Endpoint.initWithTransport(
//!     allocator,
//!     adapter.asTransport(),
//!     &quic_config,
//! );
//! defer endpoint.deinit();
//! ```
//!
//! ## Phase 15: TLS Handshake Integration Requirements (CURRENT)
//!
//! Phase 15 documents the requirements for full TLS 1.3 handshake integration.
//! This analysis is based on surveying the existing vendor/ztls implementation
//! and understanding the integration points with the QUIC endpoint.
//!
//! ### TLS Infrastructure Overview (vendor/ztls)
//!
//! The vendor/ztls library provides a complete TLS 1.3 implementation for QUIC:
//!
//! **Core Components:**
//! - `tls13/context.zig` (1,697 lines): Main TLS driver with CRYPTO frame processing
//! - `tls13/handshake_state.zig`: State machine (initial → negotiating → keys_installed → application_ready)
//! - `tls13/key_derivation.zig`: HKDF-based secret derivation (RFC 8446 §7.1)
//! - `tls13/callbacks.zig`: QUIC integration callbacks
//! - `key_schedule.zig`: HKDF operations using std.crypto (RFC 8446 §7)
//! - `record/protection.zig`: AEAD encryption/decryption (AES-GCM, ChaCha20-Poly1305)
//!
//! **Message Parsing:**
//! - `tls13/messages/client_hello.zig`: ClientHello parsing (RFC 8446 §4.1.2)
//! - `tls13/messages/server_hello.zig`: ServerHello parsing (RFC 8446 §4.1.3)
//! - `tls13/messages/finished.zig`: Finished message (RFC 8446 §4.4.4)
//! - `quic_transport_params.zig`: QUIC transport parameters (RFC 9001 §8.2)
//!
//! **Certificate Infrastructure:**
//! - `x509.zig`: X.509 certificate parsing and validation (RFC 5280)
//! - `sig.zig`: Signature verification (ECDSA, RSA-PSS, Ed25519)
//! - `tests/test_certs/`: Test PKI infrastructure (CA chain, leaf certificates)
//!
//! ### TLS Integration Points (RFC 9001 §4)
//!
//! **1. Context Creation and Configuration**
//!
//! ```zig
//! const tls_config = ztls.Config{
//!     .role = .Server,  // or .Client
//!     .alpn = &[_][]const u8{"test"},
//!     .certificate_chain = server_cert_chain,
//!     .private_key = server_private_key,
//!     .trust_store = null,  // For testing
//! };
//!
//! const callbacks = ztls.Callbacks{
//!     .on_secret_available = installSecret,
//!     .on_handshake_complete = onComplete,
//!     .on_handshake_metadata = onMetadata,
//! };
//!
//! var tls_ctx = try ztls.Context.init(allocator, tls_config, callbacks);
//! defer tls_ctx.deinit();
//! ```
//!
//! **2. CRYPTO Frame Processing (RFC 9001 §4)**
//!
//! QUIC carries TLS messages in CRYPTO frames instead of TLS records:
//!
//! ```zig
//! // Client: Generate ClientHello in Initial packet
//! const client_hello_data = try tls_ctx.getOutgoingCrypto(.Initial);
//! try endpoint.sendCryptoFrame(.Initial, client_hello_data);
//!
//! // Server: Process ClientHello, generate ServerHello
//! try tls_ctx.processCrypto(.Initial, received_crypto_data);
//! const server_hello_data = try tls_ctx.getOutgoingCrypto(.Initial);
//! try endpoint.sendCryptoFrame(.Initial, server_hello_data);
//!
//! // Continue for Handshake encryption level
//! try tls_ctx.processCrypto(.Handshake, received_crypto_data);
//! ```
//!
//! **3. Key Installation Callbacks (RFC 9001 §5)**
//!
//! As the handshake progresses, TLS derives traffic secrets and notifies QUIC:
//!
//! ```zig
//! fn installSecret(
//!     ctx: *anyopaque,
//!     level: ztls.EncryptionLevel,
//!     direction: ztls.TrafficDirection,
//!     secret: []const u8,
//! ) void {
//!     const endpoint: *Endpoint = @ptrCast(@alignCast(ctx));
//!
//!     // Derive packet protection keys from traffic secret
//!     const keys = derivePacketProtectionKeys(secret, level);
//!
//!     // Install keys for send/recv packet protection
//!     endpoint.installKeys(level, direction, keys);
//! }
//! ```
//!
//! **4. Handshake State Machine (RFC 8446 §4)**
//!
//! The TLS handshake progresses through well-defined phases:
//!
//! - **Initial**: ClientHello → ServerHello (Initial keys)
//! - **Negotiating**: Certificate, CertificateVerify (Handshake keys)
//! - **Keys Installed**: Finished messages (Handshake keys)
//! - **Application Ready**: Application traffic (Application keys)
//!
//! **5. Transport Parameter Exchange (RFC 9001 §8.2)**
//!
//! QUIC transport parameters are carried in TLS extension 0x0039:
//!
//! ```zig
//! // Server sends transport params in EncryptedExtensions
//! const transport_params = quic.TransportParameters{
//!     .initial_max_data = 1048576,
//!     .initial_max_stream_data_bidi_local = 262144,
//!     // ... other parameters
//! };
//! tls_config.transport_parameters = transport_params;
//!
//! // Client receives and validates params in callback
//! fn onMetadata(
//!     ctx: *anyopaque,
//!     metadata: ztls.HandshakeMetadata,
//! ) void {
//!     const peer_params = metadata.transport_parameters;
//!     // Validate and store peer parameters
//! }
//! ```
//!
//! ### Certificate Management Requirements
//!
//! **Test Certificate Infrastructure (vendor/ztls/tests/test_certs/):**
//!
//! - `root_cert.pem` / `root_key.pem`: Root CA certificate and private key
//! - `intermediate_cert.pem` / `intermediate_key.pem`: Intermediate CA
//! - `leaf_cert.pem` / `leaf_key.pem`: Leaf (end-entity) certificate
//! - Multiple signature algorithms: P-256, P-384, Ed25519, RSA-2048
//! - Both PEM and DER formats available
//!
//! **Loading Certificates:**
//!
//! ```zig
//! const CertificateChain = struct {
//!     leaf: []const u8,      // DER-encoded leaf certificate
//!     intermediates: [][]const u8,  // DER-encoded intermediate certs
//! };
//!
//! fn loadTestCertificates(allocator: Allocator) !CertificateChain {
//!     const leaf_pem = @embedFile("vendor/ztls/tests/test_certs/leaf_cert.pem");
//!     const leaf_der = try parsePemCertificate(allocator, leaf_pem);
//!     // ... load intermediate certs
//!     return CertificateChain{ .leaf = leaf_der, .intermediates = &.{} };
//! }
//! ```
//!
//! ### Integration Complexity Breakdown
//!
//! **Phase 16: Basic TLS Integration (15-20 hours)**
//! - Certificate loading utilities (2-3 hours)
//! - TLS Context creation with callbacks (3-4 hours)
//! - CRYPTO frame send/recv helpers (4-5 hours)
//! - Key installation callback implementation (3-4 hours)
//! - Basic handshake test (client→server, no assertions) (3-4 hours)
//!
//! **Phase 17: Full Handshake Validation (10-15 hours)**
//! - ClientHello/ServerHello parsing validation (3-4 hours)
//! - Certificate verification assertions (2-3 hours)
//! - Transport parameter exchange validation (2-3 hours)
//! - Handshake completion detection (1-2 hours)
//! - Connection state synchronization (2-3 hours)
//!
//! **Phase 18: Advanced Scenarios (15-20 hours)**
//! - Handshake failure handling (TLS alerts, errors) (4-5 hours)
//! - Packet loss recovery during handshake (3-4 hours)
//! - Key update testing (3-4 hours)
//! - 0-RTT early data (optional) (5-7 hours)
//!
//! **Total Estimated Effort: 40-55 hours (5-7 week sprint)**
//!
//! ### Next Steps for Phase 16
//!
//! Phase 16 will implement basic TLS integration:
//!
//! 1. Create certificate loading utilities in `certificate_helpers.zig`
//! 2. Add TLS Context wrapper with QUIC callbacks
//! 3. Implement CRYPTO frame helpers in EndpointWrapper
//! 4. Add key installation callback to Endpoint
//! 5. Create first basic handshake test (no validation, just completion)
//! 6. Document integration patterns and common pitfalls

const std = @import("std");
const testing = std.testing;
const loopback = @import("loopback"); // Module import (configured in build.zig)
const adapter_mod = @import("loopback_transport_adapter"); // Module import (configured in build.zig)

// Production endpoint imports (Phase 14: Real endpoint integration - ENABLED)
// These imports are provided by build.zig module configuration
// When build system is not configured, tests will skip gracefully
const endpoint_mod = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const config_mod = @import("quic_config");
const test_certs = @import("test_certs");

/// Re-export types for convenience
pub const LoopbackTransportAdapter = adapter_mod.LoopbackTransportAdapter;
pub const Transport = adapter_mod.Transport;
pub const Connection = conn_mod.Connection;

/// Endpoint role
pub const EndpointRole = enum {
    Client,
    Server,
};

/// Production endpoint wrapper for integration testing (Phase 14 - COMPLETED)
///
/// This struct wraps a real QUIC Endpoint created with loopback transport.
/// Phase 14 completion: Replaces stub implementation with real endpoint integration.
///
/// The wrapper provides the interface needed for integration testing while using
/// the production Endpoint implementation internally.
pub const EndpointWrapper = struct {
    /// Real production endpoint (heap-allocated)
    endpoint: *endpoint_mod.Endpoint,
    /// Adapter reference for cleanup (owned by helper)
    adapter: *adapter_mod.LoopbackTransportAdapter,
    /// Endpoint role (Client or Server)
    role: EndpointRole,
    /// Memory allocator
    allocator: std.mem.Allocator,
    /// Heap-allocated allocator pointer (for cleanup)
    alloc_ptr: *std.mem.Allocator,

    /// Initialize endpoint wrapper with real production endpoint
    ///
    /// Creates a QUIC endpoint using Endpoint.initWithTransport() with the
    /// loopback adapter's transport interface. This enables deterministic
    /// testing with in-memory packet exchange.
    ///
    /// Phase 14: This now creates a REAL endpoint, not a stub!
    pub fn init(
        allocator: std.mem.Allocator,
        adapter: *adapter_mod.LoopbackTransportAdapter,
        role: EndpointRole,
    ) !EndpointWrapper {
        // Create minimal QuicConfig for testing
        // Only alpn is required, allow_insecure enables testing without real certs
        const quic_config = config_mod.QuicConfig{
            .alpn = &[_][]const u8{"test"},
            .allow_insecure = true, // For testing only - skip cert verification
            .max_idle_timeout_ms = 30000,
            .max_udp_payload = 1350,
            .inline_server_cert_der = test_certs.server_cert_der,
            .inline_server_priv_p256 = test_certs.server_key_der,
        };

        // Heap-allocate endpoint (required because we return a pointer)
        const ep = try allocator.create(endpoint_mod.Endpoint);
        errdefer allocator.destroy(ep);

        // Heap-allocate allocator pointer (required because Endpoint stores pointer)
        // Phase 21 fix: Must outlive the EndpointWrapper to avoid dangling pointer
        const alloc_ptr = try allocator.create(std.mem.Allocator);
        errdefer allocator.destroy(alloc_ptr);
        alloc_ptr.* = allocator;

        // Create real endpoint with loopback transport
        // This is the Phase 14 completion: using initWithTransport() as documented
        // Phase 21 fix: Now correctly passing role parameter and heap-allocated allocator!
        const endpoint_role = if (role == .Client)
            endpoint_mod.EndpointRole.Client
        else
            endpoint_mod.EndpointRole.Server;
        ep.* = try endpoint_mod.Endpoint.initWithTransport(
            alloc_ptr,
            adapter.asTransport(),
            &quic_config,
            endpoint_role,
        );

        return EndpointWrapper{
            .endpoint = ep,
            .adapter = adapter,
            .role = role,
            .allocator = allocator,
            .alloc_ptr = alloc_ptr,
        };
    }

    /// Clean up endpoint resources
    ///
    /// Phase 14: Now properly cleans up real endpoint
    /// Phase 21 fix: Also clean up heap-allocated allocator pointer
    pub fn deinit(self: *EndpointWrapper) void {
        self.endpoint.deinit();
        self.allocator.destroy(self.endpoint);

        // Clean up heap-allocated allocator pointer
        self.allocator.destroy(self.alloc_ptr);

        // Adapter is owned by helper, not cleaned up here
    }

    /// Get the transport interface for this endpoint
    ///
    /// Phase 14: Returns real endpoint's transport
    pub fn getTransport(self: *EndpointWrapper) *adapter_mod.Transport {
        return &self.endpoint.transport;
    }
};

/// Configuration for loopback transport (re-exported for convenience)
pub const LoopbackConfig = loopback.LoopbackTransport.Config;

/// Configuration for endpoint creation
pub const EndpointConfig = struct {
    role: EndpointRole,
    max_idle_timeout_ms: u64 = 30000,
    initial_max_data: u64 = 1048576, // 1MB
    max_concurrent_bidi_streams: u64 = 100,
    enable_0rtt: bool = false,
    alpn: []const []const u8 = &[_][]const u8{"test"},
};

/// Helper for endpoint-loopback integration testing
pub const EndpointLoopbackHelper = struct {
    allocator: std.mem.Allocator,
    loopback_transport: ?*loopback.LoopbackTransport,
    loopback_config: LoopbackConfig,
    client_adapter: ?*adapter_mod.LoopbackTransportAdapter,
    server_adapter: ?*adapter_mod.LoopbackTransportAdapter,

    /// Initialize helper
    pub fn init(allocator: std.mem.Allocator) !EndpointLoopbackHelper {
        return EndpointLoopbackHelper{
            .allocator = allocator,
            .loopback_transport = null,
            .loopback_config = .{},
            .client_adapter = null,
            .server_adapter = null,
        };
    }

    /// Deinitialize helper and clean up resources
    pub fn deinit(self: *EndpointLoopbackHelper) void {
        if (self.client_adapter) |adapter| {
            self.allocator.destroy(adapter);
        }
        if (self.server_adapter) |adapter| {
            self.allocator.destroy(adapter);
        }
        if (self.loopback_transport) |transport| {
            transport.deinit();
            // Note: init() already called allocator.create(), so deinit() frees it
        }
    }

    /// Create and initialize loopback transport
    pub fn createLoopbackTransport(self: *EndpointLoopbackHelper) !*loopback.LoopbackTransport {
        if (self.loopback_transport == null) {
            self.loopback_transport = try loopback.LoopbackTransport.init(self.allocator, self.loopback_config);
        }
        return self.loopback_transport.?;
    }

    /// Create client endpoint with loopback transport
    ///
    /// Creates a LoopbackTransportAdapter for SideA (client) and returns
    /// an EndpointWrapper that can be used for testing.
    pub fn createClientEndpoint(self: *EndpointLoopbackHelper) !EndpointWrapper {
        // Ensure loopback transport is created
        const lb = try self.createLoopbackTransport();

        // Create client adapter (SideA) if not already created
        if (self.client_adapter == null) {
            const adapter = try self.allocator.create(adapter_mod.LoopbackTransportAdapter);
            adapter.* = adapter_mod.LoopbackTransportAdapter.init(lb, .SideA);
            self.client_adapter = adapter;
        }

        return EndpointWrapper.init(self.allocator, self.client_adapter.?, .Client);
    }

    /// Create server endpoint with loopback transport
    ///
    /// Creates a LoopbackTransportAdapter for SideB (server) and returns
    /// an EndpointWrapper that can be used for testing.
    pub fn createServerEndpoint(self: *EndpointLoopbackHelper) !EndpointWrapper {
        // Ensure loopback transport is created
        const lb = try self.createLoopbackTransport();

        // Create server adapter (SideB) if not already created
        if (self.server_adapter == null) {
            const adapter = try self.allocator.create(adapter_mod.LoopbackTransportAdapter);
            adapter.* = adapter_mod.LoopbackTransportAdapter.init(lb, .SideB);
            self.server_adapter = adapter;
        }

        return EndpointWrapper.init(self.allocator, self.server_adapter.?, .Server);
    }

    /// Build QuicConfig from EndpointConfig
    ///
    /// NOTE: This is a stub. Actual implementation would convert EndpointConfig
    /// to the production QuicConfig format.
    fn buildQuicConfig(self: *EndpointLoopbackHelper, role: EndpointRole) void {
        _ = self;
        _ = role;
        // TODO: Convert EndpointConfig to QuicConfig
    }

    /// Connect client to server endpoint
    ///
    /// For Phase 13, this validates that both endpoints can communicate through
    /// the adapter. Full connection establishment will be implemented in later phases.
    pub fn connectClientToServer(
        self: *EndpointLoopbackHelper,
        client: *EndpointWrapper,
        server: *EndpointWrapper,
    ) !void {
        _ = self;

        // Validate that client and server use compatible transport
        const client_transport = client.getTransport();
        const server_transport = server.getTransport();

        // Test bidirectional communication
        const test_message = "connection-test";
        const peer_addr = adapter_mod.SockAddr.ipv4(127, 0, 0, 1, 443);

        // Client sends to server
        _ = try client_transport.send(peer_addr, test_message);

        // Server should receive it
        var buf: [1500]u8 = undefined;
        const result = try server_transport.recv(&buf);

        if (result.n != test_message.len) {
            return error.ConnectionTestFailed;
        }
    }

    /// Wait for handshake completion with timeout
    ///
    /// For Phase 13, this is a simplified placeholder. Full handshake polling
    /// will be implemented when production endpoint integration is complete.
    pub fn waitForHandshake(
        self: *EndpointLoopbackHelper,
        client: *EndpointWrapper,
        server: *EndpointWrapper,
        timeout_ms: u64,
    ) !void {
        _ = self;
        _ = client;
        _ = server;
        _ = timeout_ms;

        // TODO: Poll both endpoints until handshake completes or timeout
        // This will require the production endpoint's poll() and isHandshakeComplete() APIs
    }

    /// Advance mock time for testing timeouts
    ///
    /// This is useful for testing PTO, idle timeout, and other time-based logic
    /// without waiting for real time to pass.
    pub fn advanceTime(self: *EndpointLoopbackHelper, ms: u64) !void {
        const transport = self.loopback_transport orelse return error.TransportNotInitialized;
        // TODO: Implement time advancement in loopback transport
        _ = transport;
        _ = ms;
    }
};

/// Helper function to create a basic client-server test scenario
///
/// This provides a simple way to set up a client-server pair for testing.
/// The returned helper manages cleanup automatically.
pub fn createBasicScenario(allocator: std.mem.Allocator) !EndpointLoopbackHelper {
    var helper = try EndpointLoopbackHelper.init(allocator);
    errdefer helper.deinit();

    // Default configuration suitable for most tests
    helper.loopback_config = .{
        .loss_rate = 0.0,
        .delay_ms = 0,
    };

    return helper;
}

/// Helper function to create a scenario with packet loss
///
/// Useful for testing loss recovery and retransmission logic.
pub fn createLossyScenario(allocator: std.mem.Allocator, loss_rate: f32) !EndpointLoopbackHelper {
    var helper = try EndpointLoopbackHelper.init(allocator);
    errdefer helper.deinit();

    helper.loopback_config = .{
        .loss_rate = loss_rate,
        .delay_ms = 10,
        .jitter_ms = 5,
    };

    return helper;
}

/// Helper function to create a scenario with network delay
///
/// Useful for testing RTT estimation and PTO calculations.
pub fn createDelayedScenario(allocator: std.mem.Allocator, delay_ms: u32, jitter_ms: u32) !EndpointLoopbackHelper {
    var helper = try EndpointLoopbackHelper.init(allocator);
    errdefer helper.deinit();

    helper.loopback_config = .{
        .delay_ms = delay_ms,
        .jitter_ms = jitter_ms,
    };

    return helper;
}

// =============================================================================
// Infrastructure Tests
// =============================================================================

test "EndpointLoopbackHelper initialization" {
    var helper = try EndpointLoopbackHelper.init(testing.allocator);
    defer helper.deinit();

    try testing.expect(helper.loopback_transport == null);
    try testing.expectEqual(@as(f32, 0.0), helper.loopback_config.loss_rate);
}

test "createBasicScenario provides clean defaults" {
    var helper = try createBasicScenario(testing.allocator);
    defer helper.deinit();

    try testing.expectEqual(@as(f32, 0.0), helper.loopback_config.loss_rate);
    try testing.expectEqual(@as(u32, 0), helper.loopback_config.delay_ms);
}

test "createLossyScenario configures packet loss" {
    var helper = try createLossyScenario(testing.allocator, 0.1);
    defer helper.deinit();

    try testing.expectEqual(@as(f32, 0.1), helper.loopback_config.loss_rate);
}

test "createDelayedScenario configures delay" {
    var helper = try createDelayedScenario(testing.allocator, 50, 10);
    defer helper.deinit();

    try testing.expectEqual(@as(u32, 50), helper.loopback_config.delay_ms);
    try testing.expectEqual(@as(u32, 10), helper.loopback_config.jitter_ms);
}

// =============================================================================
// Phase 13: Adapter Integration Tests
// =============================================================================

test "createClientEndpoint returns working endpoint wrapper" {
    var helper = try EndpointLoopbackHelper.init(testing.allocator);
    defer helper.deinit();

    var client = try helper.createClientEndpoint();
    defer client.deinit();

    // Verify endpoint wrapper is initialized correctly
    try testing.expect(client.role == .Client);
    try testing.expect(client.adapter == helper.client_adapter.?);
}

test "createServerEndpoint returns working endpoint wrapper" {
    var helper = try EndpointLoopbackHelper.init(testing.allocator);
    defer helper.deinit();

    var server = try helper.createServerEndpoint();
    defer server.deinit();

    // Verify endpoint wrapper is initialized correctly
    try testing.expect(server.role == .Server);
    try testing.expect(server.adapter == helper.server_adapter.?);
}

test "client and server endpoints can communicate through adapter" {
    var helper = try EndpointLoopbackHelper.init(testing.allocator);
    defer helper.deinit();

    var client = try helper.createClientEndpoint();
    defer client.deinit();

    var server = try helper.createServerEndpoint();
    defer server.deinit();

    // Get transports
    const client_transport = client.getTransport();
    const server_transport = server.getTransport();

    // Test bidirectional communication
    const msg_to_server = "Hello Server";
    const msg_to_client = "Hello Client";
    const peer_addr = adapter_mod.SockAddr.ipv4(127, 0, 0, 1, 443);

    // Client sends to server
    _ = try client_transport.send(peer_addr, msg_to_server);

    // Server receives from client
    var buf1: [1500]u8 = undefined;
    const result1 = try server_transport.recv(&buf1);
    try testing.expectEqual(@as(usize, msg_to_server.len), result1.n);
    try testing.expectEqualStrings(msg_to_server, buf1[0..result1.n]);

    // Server sends to client
    _ = try server_transport.send(peer_addr, msg_to_client);

    // Client receives from server
    var buf2: [1500]u8 = undefined;
    const result2 = try client_transport.recv(&buf2);
    try testing.expectEqual(@as(usize, msg_to_client.len), result2.n);
    try testing.expectEqualStrings(msg_to_client, buf2[0..result2.n]);
}

test "connectClientToServer validates transport connectivity" {
    var helper = try EndpointLoopbackHelper.init(testing.allocator);
    defer helper.deinit();

    var client = try helper.createClientEndpoint();
    defer client.deinit();

    var server = try helper.createServerEndpoint();
    defer server.deinit();

    // Should successfully validate connectivity
    try helper.connectClientToServer(&client, &server);
}

test "endpoint integration with packet loss" {
    var helper = try EndpointLoopbackHelper.init(testing.allocator);
    defer helper.deinit();

    // Configure 50% packet loss
    helper.loopback_config.loss_rate = 0.5;

    var client = try helper.createClientEndpoint();
    defer client.deinit();

    var server = try helper.createServerEndpoint();
    defer server.deinit();

    const client_transport = client.getTransport();
    const server_transport = server.getTransport();

    // Send multiple messages, some will be lost
    const peer_addr = adapter_mod.SockAddr.ipv4(127, 0, 0, 1, 443);
    var sent: usize = 0;
    var received: usize = 0;

    var i: usize = 0;
    while (i < 20) : (i += 1) {
        const msg = "test";
        _ = try client_transport.send(peer_addr, msg);
        sent += 1;

        var buf: [1500]u8 = undefined;
        const result = server_transport.recv(&buf) catch |err| {
            if (err == error.WouldBlock) continue;
            return err;
        };

        if (result.n == msg.len) {
            received += 1;
        }
    }

    // With 50% loss, we should receive less than what we sent
    try testing.expect(received < sent);
    try testing.expect(received > 0); // But should receive at least some
}
