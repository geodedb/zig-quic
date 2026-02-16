# QUIC Transport Layer API

The transport layer provides a high-level, easy-to-use interface for building QUIC applications. It handles connection management, stream lifecycle, and TLS certificate management automatically.

## Features

- **Secure TLS Defaults**: Requires explicit certificates; optional self-signed generation for local testing
- **Connection Pooling**: Manages multiple connections efficiently
- **Stream Management**: Easy-to-use stream API with read/write helpers
- **Client & Server**: Full support for both client and server sides
- **Structured Logging**: JSON-formatted logs for monitoring and debugging
- **Error Handling**: Comprehensive error types for robust applications

## API Overview

### Server-Side API

#### QuicTransport

Main server-side type for accepting connections.

```zig
const transport = @import("quic").transport;

const config = transport.QuicTransport.Config{
    .address = "0.0.0.0",
    .port = 4433,
    .max_connections = 100,
    .idle_timeout_ms = 30000,
    .cert_path = "certs/server.crt",
    .key_path = "certs/server.key",
};

var quic_transport = try transport.QuicTransport.init(allocator, config);
defer quic_transport.deinit();

// Start listening
try quic_transport.listen();

// Accept connections in a loop
while (true) {
    try quic_transport.poll(10); // Poll for incoming packets

    const conn = quic_transport.accept() catch |err| {
        if (err == transport.QuicError.WouldBlock) continue;
        return err;
    };

    // Handle connection...
}
```

#### QuicConnection

Represents an established QUIC connection.

```zig
// Accept a stream from the client
const stream = try conn.acceptStream();
defer stream.close();

// Or open a new stream to the client
const new_stream = try conn.openStream(true); // true = bidirectional
defer new_stream.close();
```

#### QuicStream

Represents a QUIC stream with read/write operations.

```zig
// Read data
var buf: [4096]u8 = undefined;
const n = try stream.read(&buf);

// Write data
const written = try stream.write("Hello, QUIC!");
_ = written;

// Write all data (handles fragmentation)
try stream.writeAll(large_data);

// Read a line (useful for text protocols)
const line = try stream.readLine(1024);
defer allocator.free(line);
```

### Client-Side API

#### QuicClient

Client-side connection type.

```zig
var client = transport.QuicClient.init(allocator);
defer client.deinit();

// Connect to server
try client.connectEx("127.0.0.1", 4433, "certs/ca.crt", null, null);

// Wait for handshake to complete
try client.waitForHandshake(5);

// Get a stream
const stream = try client.getStream();
defer stream.deinit();

// Use the stream
try stream.writeAll("GET / HTTP/1.1\r\n\r\n");
var buf: [4096]u8 = undefined;
const n = try stream.read(&buf);
```

### Error Types

```zig
pub const QuicError = error{
    InitFailed,
    ConnectionFailed,
    StreamFailed,
    WriteError,
    ReadError,
    InvalidAddress,
    CertificateError,
    EndpointInitFailed,
    AcceptFailed,
    HandshakeError,
    Timeout,
    WouldBlock,
    Closed,
    InvalidState,
    HandshakeFailed,
    TransportParametersFailed,
    FlowControlViolation,
    ProtocolViolation,
    IdleTimeout,
    ConnectionClosed,
};
```

## Configuration

### QuicTransport.Config

Server-side configuration options:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `address` | `[]const u8` | `"0.0.0.0"` | Bind address |
| `port` | `u16` | `7567` | Bind port |
| `max_connections` | `usize` | `1000` | Maximum concurrent connections |
| `idle_timeout_ms` | `u64` | `30000` | Idle timeout in milliseconds |
| `max_stream_data` | `u64` | `10MB` | Maximum data per stream |
| `max_data` | `u64` | `100MB` | Maximum data per connection |
| `cert_path` | `?[]const u8` | `null` | Path to TLS certificate |
| `key_path` | `?[]const u8` | `null` | Path to TLS private key |
| `ca_path` | `?[]const u8` | `null` | Path to CA certificate (for mTLS) |
| `allow_insecure` | `bool` | `false` | Skip certificate validation (testing only) |
| `auto_generate_certs` | `bool` | `false` | Auto-generate self-signed cert/key (testing only) |

## Examples

### Simple HTTP/1.1-style Server

```zig
const std = @import("std");
const transport = @import("quic").transport;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = transport.QuicTransport.Config{
        .port = 8443,
        .cert_path = "certs/server.crt",
        .key_path = "certs/server.key",
    };

    var quic_transport = try transport.QuicTransport.init(allocator, config);
    defer quic_transport.deinit();

    try quic_transport.listen();
    std.debug.print("Server listening on port {d}\n", .{config.port});

    while (true) {
        try quic_transport.poll(10);

        const conn = quic_transport.accept() catch |err| {
            if (err == transport.QuicError.ConnectionFailed) continue;
            return err;
        };

        const thread = try std.Thread.spawn(.{}, handleConnection, .{conn});
        thread.detach();
    }
}

fn handleConnection(conn: *transport.QuicConnection) void {
    defer conn.close();

    const stream = conn.acceptStream() catch return;
    defer stream.close();

    var buf: [4096]u8 = undefined;
    const n = stream.read(&buf) catch return;

    const response = "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: 13\r\n\r\n" ++
        "Hello, QUIC!\n";
    stream.writeAll(response) catch return;
}
```

### Simple Client

```zig
const std = @import("std");
const transport = @import("quic").transport;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = transport.QuicClient.init(allocator);
    defer client.deinit();

    try client.connectEx("127.0.0.1", 8443, "certs/ca.crt", null, null);
    try client.waitForHandshake(5);

    const stream = try client.getStream();
    defer stream.deinit();

    try stream.writeAll("GET / HTTP/1.1\r\n\r\n");

    var buf: [4096]u8 = undefined;
    const n = try stream.read(&buf);

    std.debug.print("Response: {s}\n", .{buf[0..n]});
}
```

## Certificate Management

The transport layer requires explicit certificates by default:

1. **Explicit Certificates**: Provide `cert_path` and `key_path` in the configuration
2. **Optional Auto-Generation**: Set `auto_generate_certs = true` to create self-signed certs for local testing
3. **No Fail-Open**: Missing or invalid certs return an error instead of disabling TLS

### Generating Certificates Manually

```bash
# Generate self-signed ECDSA P-256 certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout certs/server.key \
    -out certs/server.crt \
    -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Company/CN=localhost"
```

For local development, you can also run `./create_test_certs.sh` to generate
test certificates under `tests/certs/` and point `cert_path`/`key_path` there
(testing only).

## Logging

The transport layer outputs structured JSON logs for easy parsing:

```json
{"component":"transport","transport":"quic","tls":"true","port":4433}
{"level":"DEBUG","component":"quic_server","msg":"server startup","use_tls":true}
{"level":"DEBUG","component":"quic_server","msg":"connection accepted","total_connections":1}
```

## Best Practices

1. **Always close resources**: Use `defer` to ensure connections and streams are properly closed.
2. **Use the nonblocking contract**: Treat `QuicError.WouldBlock` as retryable control flow.
3. **Use transport-owned cleanup**: Call `destroyConnection(conn)` from workers and `drainPendingDestroy()` in the main poll/accept loop.
4. **Poll regularly**: Call `poll()` regularly to process incoming packets and timers.
5. **Wait for handshake**: Always call `waitForHandshake(timeout_secs)` on the client before using streams.

## Advanced Features

### Connection with mTLS

Enable mutual TLS by providing a CA certificate:

```zig
const config = transport.QuicTransport.Config{
    .port = 8443,
    .cert_path = "certs/server.crt",
    .key_path = "certs/server.key",
    .ca_path = "certs/ca.crt", // Require client certificates
};
```

### Insecure Connections (Testing Only)

For testing, you can connect without certificate validation:

```zig
try client.connectInsecure("127.0.0.1", 8443, true);
```

**Warning**: Never use insecure connections in production!

## Performance Considerations

- **Connection Pooling**: The transport layer maintains a pool of active connections
- **Stream Multiplexing**: Multiple streams can be active on a single connection
- **Flow Control**: Automatic flow control prevents overwhelming the receiver
- **Congestion Control**: Built-in NewReno congestion control algorithm

## See Also

- [QUIC Protocol Specification](https://www.rfc-editor.org/rfc/rfc9000.html)
- [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [Geode And Dependent-System Migration Guide](GEODE_TRANSPORT_MIGRATION.md)
