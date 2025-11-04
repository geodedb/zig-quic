// QUIC: A UDP-Based Multiplexed and Secure Transport (RFC 9000)
//
// QUIC is a secure general-purpose transport protocol.  This document
// defines version 1 of QUIC, which conforms to the version-independent
// properties of QUIC defined in [QUIC-INVARIANTS].

// QUIC is a connection-oriented protocol that creates a stateful
// interaction between a client and server.

// The QUIC handshake combines negotiation of cryptographic and
// transport parameters.  QUIC integrates the TLS handshake [TLS13],
// although using a customized framing for protecting packets.  The
// integration of TLS and QUIC is described in more detail in
// [QUIC-TLS].  The handshake is structured to permit the exchange of
// application data as soon as possible.  This includes an option for
// clients to send data immediately (0-RTT), which requires some form of
// prior communication or configuration to enable.

// Endpoints communicate in QUIC by exchanging QUIC packets.  Most
// packets contain frames, which carry control information and
// application data between endpoints.  QUIC authenticates the entirety
// of each packet and encrypts as much of each packet as is practical.
// QUIC packets are carried in UDP datagrams [UDP] to better facilitate
// deployment in existing systems and networks.

// Application protocols exchange information over a QUIC connection via
// streams, which are ordered sequences of bytes.  Two types of streams
// can be created: bidirectional streams, which allow both endpoints to
// send data; and unidirectional streams, which allow a single endpoint
// to send data.  A credit-based scheme is used to limit stream creation
// and to bound the amount of data that can be sent.

// QUIC provides the necessary feedback to implement reliable delivery
// and congestion control.  An algorithm for detecting and recovering
// from loss of data is described in Section 6 of [QUIC-RECOVERY].  QUIC
// depends on congestion control to avoid network congestion.  An
// exemplary congestion control algorithm is described in Section 7 of
// [QUIC-RECOVERY].

// QUIC connections are not strictly bound to a single network path.
// Connection migration uses connection identifiers to allow connections
// to transfer to a new network path.  Only clients are able to migrate
// in this version of QUIC.  This design also allows connections to
// continue after changes in network topology or address mappings, such
// as might be caused by NAT rebinding.

// Once established, multiple options are provided for connection
// termination.  Applications can manage a graceful shutdown, endpoints
// can negotiate a timeout period, errors can cause immediate connection
// teardown, and a stateless mechanism provides for termination of
// connections after one endpoint has lost state.
const api = @import("src/quic/api.zig");
pub const pem = @import("src/quic/pem.zig");

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
pub const tryAccept = api.tryAccept;
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
pub const acceptStream = api.acceptStream;
pub const poll = api.poll;
pub const scheduleTimer = api.scheduleTimer;
pub const cancelTimer = api.cancelTimer;
pub const isHandshakeConfirmed = api.isHandshakeConfirmed;
pub const close = api.close;
pub const destroy = api.destroy;
pub const handshakeDoneSeen = api.handshakeDoneSeen;
pub const isDrained = api.isDrained;
pub const flush = api.flush;

pub const hasIncomingStreams = api.hasIncomingStreams;
pub const getFirstStream = api.getFirstStream;
