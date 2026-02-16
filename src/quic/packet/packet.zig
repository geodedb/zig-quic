// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUIC packet encoding coordinator module.
//!
//! This module provides the modular packet API by combining specialized
//! packet modules and re-exporting legacy implementations.
//!
//! RFC 9000 §17: Packet Formats
//! RFC 9001 §5: Packet Protection

const std = @import("std");

// Import packet submodules
pub const types = @import("types");
pub const header = @import("header.zig");

// Import legacy packet.zig for current implementations
const legacy = @import("../packet.zig");

// Re-export types from types module and legacy implementations
pub const PacketNumber = types.PacketNumber;
pub const LongHeaderType = types.LongHeaderType;
pub const DecodedShort = legacy.DecodedShort; // Use legacy type to match decodeShortProtected return
pub const DecodedShortView = legacy.DecodedShortView;
pub const DecodedInitial = legacy.DecodedInitial; // Use legacy type to match decodeInitialProtected return
pub const DecodedVN = types.DecodedVN;
pub const QUIC_V1 = types.QUIC_V1;
pub const QUIC_V2 = types.QUIC_V2;

// Re-export header types
pub const LongHeader = header.LongHeader;
pub const ShortHeader = header.ShortHeader;

// Re-export types and functions from legacy implementation
// These will be gradually migrated to dedicated modules in future phases
pub const AeadKeys = legacy.AeadKeys;
pub const InitialKeys = legacy.InitialKeys;

/// Build a fully protected Initial packet using AES-128-GCM.
/// RFC 9000 §17.2.2: Initial Packet
/// RFC 9001 §5: Packet Protection
pub const encodeInitialProtected = legacy.encodeInitialProtected;

/// Parse and remove protection from an Initial packet.
/// RFC 9000 §17.2.2: Initial Packet
pub const decodeInitialProtected = legacy.decodeInitialProtected;

/// Compute initial client/server traffic keys for QUIC v1/v2.
/// RFC 9001 §5.1: Initial Secrets
pub const derive_initial_keys = legacy.derive_initial_keys;

/// Convenience helper returning RX/TX Initial keys by endpoint role.
/// RFC 9001 §5.1.2: Client Initial (client hello)
pub const initialAeadKeys = legacy.initialAeadKeys;

/// Build a fully protected Handshake packet using AES-128-GCM.
/// RFC 9000 §17.2.4: Handshake Packet
pub const encodeHandshakeProtected = legacy.encodeHandshakeProtected;

/// Encode a protected short-header (1-RTT) packet.
/// RFC 9000 §17.3: Short Header Packets
/// RFC 9001 §5.4: Header Protection
pub const encodeShortProtected = legacy.encodeShortProtected;
pub const encodeShortProtectedInto = legacy.encodeShortProtectedInto;

/// Decode and unprotect a short-header (1-RTT) packet.
/// RFC 9000 §17.3: Short Header Packets
pub const decodeShortProtected = legacy.decodeShortProtected;
pub const decodeShortProtectedInto = legacy.decodeShortProtectedInto;
pub const decodeShortProtectedWithHpInto = legacy.decodeShortProtectedWithHpInto;

/// Legacy shim for older tests (uses largest_pn=0).
pub const decodeShortProtectedLegacy = legacy.decodeShortProtectedLegacy;

/// Encode a Version Negotiation packet.
/// RFC 9000 §17.2.1: Version Negotiation Packet
pub const encodeVersionNegotiation = legacy.encodeVersionNegotiation;

/// Decode a Version Negotiation packet.
/// RFC 9000 §17.2.1: Version Negotiation Packet
pub const decodeVersionNegotiation = legacy.decodeVersionNegotiation;

/// Check if version negotiation should be accepted.
/// RFC 9000 §6: Version Negotiation
pub const shouldAcceptVersionNegotiation = legacy.shouldAcceptVersionNegotiation;

/// Encode a Retry packet.
/// RFC 9000 §17.2.5: Retry Packet
pub const encodeRetry = legacy.encodeRetry;

/// Verify a Retry packet.
/// RFC 9000 §17.2.5: Retry Packet
pub const verifyRetry = legacy.verifyRetry;

/// Encode a 0-RTT packet.
/// RFC 9001 §4.6.1: Enabling 0-RTT
pub const encode0RTTProtected = legacy.encode0RTTProtected;

/// Decode a 0-RTT packet.
/// RFC 9001 §4.6.1: Enabling 0-RTT
pub const decode0RTTProtected = legacy.decode0RTTProtected;
