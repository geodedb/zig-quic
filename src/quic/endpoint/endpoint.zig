// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Core QUIC endpoint coordination.
//!
//! This module coordinates all endpoint sub-modules and provides the main
//! Endpoint struct that integrates:
//! - Timer management (timer.zig)
//! - Connection lookup/routing (lookup.zig)
//! - UDP I/O operations (io.zig)
//! - Client establishment (client.zig)
//! - Server acceptance (server.zig)
//! - Incoming packet processing (incoming.zig)
//! - PTO probe handling (pto.zig)
//!
//! RFC 9000 §5-9, §14: Endpoint Responsibilities
//! RFC 9002 §6: Loss Detection and Probe Timeout

const std = @import("std");

// Import all sub-modules
pub const types = @import("types");
pub const timer = @import("timer.zig");
pub const lookup = @import("lookup.zig");
pub const io = @import("io.zig");
pub const client = @import("client.zig");
pub const server = @import("server.zig");
pub const incoming = @import("incoming.zig");
pub const pto = @import("pto.zig");

// Re-export common types for convenience
pub const Timer = types.Timer;
pub const TimerKind = types.TimerKind;
pub const Key = types.Key;
pub const EndpointRole = types.EndpointRole;
pub const TimerManager = timer.TimerManager;
pub const ConnectionTable = lookup.ConnectionTable;
pub const RecvResult = io.RecvResult;
pub const ClientHandshake = client.ClientHandshake;
pub const ServerHandshake = server.ServerHandshake;
pub const IncomingProcessor = incoming.IncomingProcessor;
pub const PtoHandler = pto.PtoHandler;

// Re-export utility functions
pub const hashBytes = types.hashBytes;
pub const normalizeAddr = types.normalizeAddr;
pub const hashSockaddr = types.hashSockaddr;
pub const makeKey = lookup.makeKey;
pub const sendTo = io.sendTo;
pub const recvFrom = io.recvFrom;

/// Main Endpoint struct placeholder.
/// This will be populated with the actual Endpoint implementation
/// that coordinates all the sub-modules above.
///
/// For now, this serves as the integration point for all endpoint-related
/// functionality split across the sub-modules.
pub const Endpoint = struct {
    // This will contain fields from all sub-modules
    // and coordinate their interactions

    // Placeholder to make compilation work
    role: EndpointRole = .Server,

    pub fn init() Endpoint {
        return .{};
    }

    pub fn deinit(self: *Endpoint) void {
        _ = self;
    }
};
