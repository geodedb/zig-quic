// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Core QUIC connection state and coordination.
//!
//! This module coordinates all connection sub-modules and provides the main
//! Connection struct that integrates:
//! - Packet number management (packet_number.zig)
//! - ACK tracking (ack.zig)
//! - Stream management (stream.zig)
//! - Connection ID management (connection_id.zig)
//! - TLS handshake (handshake.zig)
//! - Path validation (path.zig)
//! - Anti-amplification (amplification.zig)
//! - PMTUD (pmtud.zig)
//! - AEAD limits (limits.zig)
//!
//! RFC 9000 §2-7: Connection State Machine
//! RFC 9001 §4: TLS Integration
//! RFC 9002 §5: Loss Detection

const std = @import("std");

// Import all sub-modules
pub const types = @import("types");
pub const crypto_buffer = @import("crypto_buffer.zig");
pub const packet_number = @import("packet_number.zig");
pub const ack = @import("ack.zig");
pub const stream = @import("stream.zig");
pub const connection_id = @import("connection_id.zig");
pub const handshake = @import("handshake.zig");
pub const path = @import("path.zig");
pub const amplification = @import("amplification.zig");
pub const pmtud = @import("pmtud.zig");
pub const limits = @import("limits.zig");

// Re-export common types for convenience
pub const Role = types.Role;
pub const SockAddr = types.SockAddr;
pub const Cid = types.Cid;
pub const SendFn = types.SendFn;
pub const CryptoBuffer = crypto_buffer.CryptoBuffer;
pub const Fragment = crypto_buffer.Fragment;
pub const PnWindow = packet_number.PnWindow;
pub const AckDesc = ack.AckDesc;
pub const EcnCounter = ack.EcnCounter;
pub const StreamRx = stream.StreamRx;
pub const StreamTx = stream.StreamTx;
pub const Segment = stream.Segment;
pub const LocalCid = connection_id.LocalCid;
pub const PathValidation = path.PathValidation;
pub const AmplificationLimits = amplification.AmplificationLimits;
pub const PmtudState = pmtud.PmtudState;
pub const AeadLimits = limits.AeadLimits;
pub const HandshakeState = handshake.HandshakeState;

// Re-export utility functions
pub const expandTruncatedPn = packet_number.expandTruncatedPn;
pub const deriveStatelessResetToken = connection_id.deriveStatelessResetToken;
