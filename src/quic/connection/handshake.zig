// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TLS handshake integration for QUIC connections.
//!
//! RFC 9001 §4: QUIC Transport Parameters Extension
//! RFC 9001 §5: Packet Protection
//! TLS 1.3 integration and key derivation for QUIC

const std = @import("std");

/// Handshake state tracking for TLS 1.3 integration.
/// RFC 9001: QUIC uses TLS 1.3 for handshake and key derivation.
pub const HandshakeState = struct {
    /// Negotiated ALPN cached for outer layers (owned slice, may be null prior to EncryptedExtensions).
    negotiated_alpn: ?[]u8 = null,

    /// Locally advertised QUIC transport parameters (encoded) cached for reuse.
    local_transport_params_raw: ?[]u8 = null,

    /// Peer-provided QUIC transport parameters (encoded) cached after validation.
    peer_transport_params_raw: ?[]u8 = null,

    pub fn deinit(self: *HandshakeState, alloc: *std.mem.Allocator) void {
        if (self.negotiated_alpn) |alpn| alloc.free(alpn);
        if (self.local_transport_params_raw) |tp| alloc.free(tp);
        if (self.peer_transport_params_raw) |tp| alloc.free(tp);
        self.negotiated_alpn = null;
        self.local_transport_params_raw = null;
        self.peer_transport_params_raw = null;
    }
};
