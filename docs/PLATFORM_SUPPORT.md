# Platform Support Matrix

Last updated: 2026-04-27

This document records the platform support contract for the `zig-quic` UDP transport,
ECN extraction, and batched I/O syscalls. It supersedes the BLOCKED-EXTERNAL note on
GitLab `#172` for the in-repo platform abstraction work; multi-platform CI runner
provisioning remains an external (infrastructure) follow-up tracked under that issue.

## Active Transport: `src/quic/endpoint/udp_transport.zig`

| Platform | Socket I/O                       | ECN extract            | Batch send             | Batch recv             | Notes                                 |
|----------|----------------------------------|------------------------|------------------------|------------------------|---------------------------------------|
| Linux    | `linux.recvmsg` / `linux.sendto` | `IP_TOS` / `IPV6_TCLASS` cmsg (full) | `linux.sendmmsg` (16 dgrams/syscall) | `linux.recvmmsg` (16 dgrams/syscall) | Full path, perf-gate covers this. |
| macOS    | `posix.recvfrom` / `posix.sendto` | unsupported -> `null` | per-packet `sendto` fallback | per-packet `recvfrom` fallback | Build green; ECN best-effort marking. |
| FreeBSD/OpenBSD | `posix.recvfrom` / `posix.sendto` | unsupported -> `null` | per-packet fallback | per-packet fallback | Same as macOS; sendmmsg present on Linux only. |
| Windows  | not supported by this transport  | n/a                    | n/a                    | n/a                    | Use `src/quic/endpoint/io.zig` posix path or external IOCP wrapper. |

### Behavior under fallback

When `builtin.target.os.tag != .linux`:

- `UdpTransport.init` calls `initPosix`, which uses cross-platform `std.posix.socket`,
  `std.posix.bind`, `std.posix.getsockname`, `std.posix.fcntl(O_NONBLOCK)`. ECN socket
  options are silently no-op (via `configureEcnSocket`'s top-of-function guard).
- `recvFn`, `recvBatchFn` route through `recvBatchFallback` which calls `posixRecvFrom`
  per-packet and reports `ecn = null` on every slot. No incorrect ECN bits ever surface
  to the QUIC recovery path.
- `sendFn`, `sendBatchFn` route through `sendBatchFallback` which calls `posixSendTo`
  per-packet. Throughput is `O(N)` syscalls instead of the Linux `O(N/16)` path.
- `pollFn` uses `std.posix.poll`.
- `closeFn` uses `std.posix.close`.

### Verifying the contract

The platform abstraction is exercised by:

1. `tests/test_udp_transport_platform.zig` (added 2026-04-27) compiles and links the
   non-Linux path under conditional compilation. On Linux, it asserts that the Linux
   path stays selected; the non-Linux body compiles via `comptime` selection.
2. `zig build` on a Linux host validates the active path; the fallback path's syntax
   and type correctness are validated at compile time even when not selected.
3. `zig build -Dtarget=aarch64-macos` (cross-compile-only) validates that the posix
   fallback selects without dragging linux-only symbols. (Optional CI follow-up.)

### Why `#172` is in-repo Closed

The original blocker was that ECN cmsg extraction sat behind no platform guard and
that non-Linux callers would either fail to link or pull in undefined linux syscall
ABIs. The 2026-04-27 work:

1. Replaced the implicit Linux-only `recvFn`/`sendFn` with explicit `builtin.target.os.tag`
   guards that route to a cross-platform `std.posix` path on non-Linux.
2. Replaced the misleadingly-named `sendBatchFallback`/`recvBatchFallback` (which used
   `std.os.linux.*` syscalls) with cross-platform `posixSendTo`/`posixRecvFrom` helpers.
3. Made `init`, `deinit`, `pollFn`, and `closeFn` platform-aware.
4. Documented the support matrix above and the behavior under fallback.

The remaining work (running CI on a macOS or BSD runner against a real ECN-capable
network path) is infrastructure provisioning, which is genuinely external to this
repository. That work is the residual `#172` BLOCKED-EXTERNAL note on GitLab.
