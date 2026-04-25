const std = @import("std");
const h3_client = @import("h3_client");
const h3_server = @import("h3_server");

test "h3 adapters classify only bounded transient transport write errors as retryable" {
    const transient = [_]anyerror{ error.WouldBlock, error.FlowControlBlocked, error.KeysNotReady };
    for (transient) |err| {
        try std.testing.expect(h3_client.isRetryableTransportError(err));
        try std.testing.expect(h3_server.H3Server.isRetryableTransportError(err));
    }

    const fatal = [_]anyerror{ error.ConnectionClosed, error.StreamStopped, error.OutOfMemory };
    for (fatal) |err| {
        try std.testing.expect(!h3_client.isRetryableTransportError(err));
        try std.testing.expect(!h3_server.H3Server.isRetryableTransportError(err));
    }
}
