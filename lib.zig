// Public API surface re-export for vendored QUIC module (geode wiring)
const api = @import("src/quic/api.zig");

pub const QuicVersion = api.QuicVersion;
pub const Role = api.Role;
pub const LoopBackend = api.LoopBackend;

pub const QuicConfig = api.QuicConfig;
pub const QuicEndpoint = api.QuicEndpoint;
pub const QuicConnection = api.QuicConnection;
pub const QuicStreamId = api.QuicStreamId;

pub const deriveInitialSecretsForConfig = api.deriveInitialSecretsForConfig;
pub const defaultLoopBackend = api.defaultLoopBackend;
pub const endpointInit = api.endpointInit;
pub const endpointDeinit = api.endpointDeinit;
pub const connect = api.connect;
pub const accept = api.accept;
pub const openStream = api.openStream;
pub const openUni = api.openUni;
pub const writeStream = api.writeStream;
pub const readStream = api.readStream;
pub const isStreamFinished = api.isStreamFinished;
pub const closeStream = api.closeStream;
pub const sendDatagram = api.sendDatagram;
pub const recvDatagram = api.recvDatagram;
pub const getNegotiatedAlpn = api.getNegotiatedAlpn;
pub const getPeerTransportParams = api.getPeerTransportParams;
pub const handshakeComplete = api.handshakeComplete;
pub const closeConnection = api.closeConnection;
pub fn closeConnectionSimple(conn: *QuicConnection) !void {
    return api.closeConnection(conn, 0);
}
pub fn acceptStream(conn: *QuicConnection) !QuicStreamId {
    _ = conn;
    return 0;
}
pub const poll = api.poll;
pub const scheduleTimer = api.scheduleTimer;
pub const cancelTimer = api.cancelTimer;
pub const isHandshakeConfirmed = api.isHandshakeConfirmed;
pub const close = api.close;
pub const destroy = api.destroy;
pub const handshakeDoneSeen = api.handshakeDoneSeen;
pub const isDrained = api.isDrained;
pub const flush = api.flush;
