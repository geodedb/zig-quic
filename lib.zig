// Wrapper module for vendored QUIC library submodule
pub const quic = @import("quic.zig");
pub const api = @import("src/quic/api.zig");

// Re-export commonly used types from the QUIC implementation
pub const Connection = api.Connection;
pub const Stream = api.Stream;
pub const Listener = api.Listener;
pub const Config = api.Config;

// Export the main QUIC types
pub usingnamespace quic;