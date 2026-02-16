const std = @import("std");
const conn_mod = @import("quic_conn");
const cfg = @import("config");
const endpoint_types = @import("types");

pub const SendFn = *const fn (peer: conn_mod.SockAddr, data: []const u8) anyerror!usize;
pub const ScheduleTimerFn = *const fn (conn: *conn_mod.Connection, kind: endpoint_types.TimerKind, delay_ms: u32) anyerror!u64;
pub const SendInitialProbeFn = *const fn (conn: *conn_mod.Connection) anyerror!void;
pub const SetupSenderFn = *const fn (conn: *conn_mod.Connection) void;

pub const RxContext = struct {
    allocator: *std.mem.Allocator,
    conns: *std.AutoHashMap(endpoint_types.Key, *conn_mod.Connection),
    accepted: *std.ArrayList(*conn_mod.Connection),
    cfg: *const cfg.QuicConfig,
    send_fn: SendFn,
    schedule_timer_fn: ScheduleTimerFn,
    send_initial_probe_fn: SendInitialProbeFn,
    setup_sender_fn: SetupSenderFn,
    test_capture_enabled: bool,
    endpoint_role: endpoint_types.EndpointRole,
    endpoint_ctx: ?*anyopaque = null,
    generated_token_secret: *const [32]u8 = undefined,
    max_connections: usize = 10000,
};
