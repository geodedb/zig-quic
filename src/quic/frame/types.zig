// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUIC frame types and common structures.
//!
//! RFC 9000 §19: Frame Types and Formats
//! RFC 9221: DATAGRAM Extension

const std = @import("std");

/// Known QUIC frame type bytes (subset).
/// RFC 9000 §19 defines frame types with specific byte values.
pub const FrameType = enum(u8) {
    PADDING = 0x00,
    PING = 0x01,
    ACK = 0x02,
    ACK_ECN = 0x03,
    RESET_STREAM = 0x04,
    STOP_SENDING = 0x05,
    CRYPTO = 0x06,
    NEW_TOKEN = 0x07,
    STREAM = 0x08, // 0x08-0x0f with flags
    MAX_DATA = 0x10,
    MAX_STREAM_DATA = 0x11,
    MAX_STREAMS_BIDI = 0x12,
    MAX_STREAMS_UNI = 0x13,
    DATA_BLOCKED = 0x14,
    STREAM_DATA_BLOCKED = 0x15,
    STREAMS_BLOCKED_BIDI = 0x16,
    STREAMS_BLOCKED_UNI = 0x17,
    NEW_CONNECTION_ID = 0x18,
    RETIRE_CONNECTION_ID = 0x19,
    PATH_CHALLENGE = 0x1a,
    PATH_RESPONSE = 0x1b,
    CONNECTION_CLOSE = 0x1c,
    APPLICATION_CLOSE = 0x1d, // RFC 9000 §19.19 - application-level close (no frame_type field)
    HANDSHAKE_DONE = 0x1e,
    DATAGRAM = 0x30, // RFC 9221 (optional)
};

/// Ack range element used inside ACK frames (gap,len VarInts).
/// RFC 9000 §19.3: ACK Frame format includes ACK ranges.
pub const AckRange = struct {
    gap: u64,
    len: u64,
};

/// ECN counters carried by ACK_ECN frame.
/// RFC 9000 §19.3.2: ACK_ECN includes ECT0, ECT1, and CE counts.
pub const EcnCounts = struct {
    ect0: u64,
    ect1: u64,
    ce: u64,
};
