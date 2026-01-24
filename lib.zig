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
// Core modules - using named imports configured in build.zig
const api = @import("quic_api");
const tls13 = @import("quic_tls13");
const frame_mod = @import("quic_frame");
const packet_mod = @import("quic_packet");
const varint_mod = @import("quic_varint");
const transport_params = @import("quic_transport_params");
const crypto_mod = @import("quic_crypto");
const config_mod = @import("config.zig");
const logger_mod = @import("quic_logger");
const h3_server_mod = @import("h3_server");
const h3_client_mod = @import("h3_client");

// ============================================================================
// Utility Modules
// ============================================================================

/// PEM certificate/key parsing utilities (re-exported from the public API)
pub const pem = api.pem;

/// Byteorder utilities (used internally by conn, endpoint, varint, and token modules)
/// Note: When using this library as a vendor dependency, you may need to configure
/// the byteorder module in your build.zig. See VENDOR_USAGE.md for details.
pub const byteorder = @import("byteorder");

/// Variable-length integer encoding/decoding (RFC 9000 §16)
pub const varint = varint_mod;

/// Logger interface for QUIC events and debugging
pub const logger = logger_mod;

// ============================================================================
// QUIC Core Types (from api.zig)
// ============================================================================

pub const QuicVersion = api.QuicVersion;
pub const Role = api.Role;
pub const LoopBackend = api.LoopBackend;

pub const QuicConfig = api.QuicConfig;
pub const QuicEndpoint = api.QuicEndpoint;
pub const QuicConnection = api.QuicConnection;
pub const QuicStreamId = api.QuicStreamId;
pub const PollStats = api.PollStats;
pub const AcceptError = api.AcceptError;

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

// ============================================================================
// TLS 1.3 Types and Functions
// ============================================================================

/// TLS 1.3 configuration for QUIC connections
pub const TlsConfig = tls13.Config;

/// TLS 1.3 context for managing handshake state
pub const TlsContext = tls13.Context;

/// TLS 1.3 callbacks for handling handshake events
pub const TlsCallbacks = tls13.Callbacks;

/// TLS handshake metadata
pub const HandshakeMetadata = tls13.HandshakeMetadata;

/// TLS handshake errors
pub const HandshakeError = tls13.HandshakeError;

/// TLS signature schemes (RFC 8446)
pub const SignatureScheme = tls13.SignatureScheme;

/// TLS encryption levels
pub const EncryptionLevel = tls13.EncryptionLevel;

/// TLS handshake phase
pub const HandshakePhase = tls13.HandshakePhase;

/// Traffic direction (send/receive)
pub const TrafficDirection = tls13.TrafficDirection;

/// Session ticket storage
pub const TicketStore = tls13.TicketStore;

/// Session ticket entry
pub const TicketEntry = tls13.TicketEntry;

/// View of a session ticket
pub const TicketEntryView = tls13.TicketEntryView;

/// ClientHello view for parsing
pub const ClientHelloView = tls13.ClientHelloView;

// ============================================================================
// QUIC Frame Types (RFC 9000 §19)
// ============================================================================

/// QUIC frame type enumeration
pub const FrameType = frame_mod.FrameType;

/// QUIC frame union type
pub const Frame = frame_mod.Frame;

/// ACK frame range
pub const AckRange = frame_mod.AckRange;

/// ECN counts for ACK frames
pub const EcnCounts = frame_mod.EcnCounts;

// ============================================================================
// QUIC Transport Parameters (RFC 9000 §18)
// ============================================================================

/// Transport parameter IDs
pub const TransportParamId = transport_params.Id;

/// Transport parameters structure
pub const TransportParams = transport_params.TransportParams;

/// Preferred address for connection migration
pub const PreferredAddress = transport_params.PreferredAddress;

// ============================================================================
// QUIC Packet Types and Functions
// ============================================================================

/// Packet module for packet encoding/decoding
pub const packet = packet_mod;

// ============================================================================
// Cryptographic Functions
// ============================================================================

/// AEAD suite enumeration (AES-128-GCM, ChaCha20-Poly1305)
pub const AeadSuite = crypto_mod.AeadSuite;

/// QUIC cryptographic keys (key, IV, header protection)
pub const QuicKeys = crypto_mod.QuicKeys;

/// Derive QUIC initial secrets from connection ID
pub const deriveInitialSecrets = crypto_mod.deriveInitialSecrets;

/// Protect a QUIC packet with AEAD encryption
pub const protectPacket = crypto_mod.protectPacket;

/// Unprotect a QUIC packet with AEAD decryption
pub const unprotectPacket = crypto_mod.unprotectPacket;

// ============================================================================
// Configuration Types
// ============================================================================

/// Detailed QUIC configuration (from config.zig)
pub const DetailedQuicConfig = config_mod.QuicConfig;

// ============================================================================
// HTTP/3 Helpers
// ============================================================================

/// HTTP/3 server/client helpers built atop the QUIC core exports.
pub const h3 = struct {
    pub const server = h3_server_mod;
    pub const client = h3_client_mod;

    pub const H3Server = h3_server_mod.H3Server;
    pub const encodeVarint = h3_client_mod.encodeVarint;
    pub const buildSimpleGetHeaders = h3_client_mod.buildSimpleGetHeaders;
    pub const buildRequestFrame = h3_client_mod.buildRequestFrame;
    pub const h3Get = h3_client_mod.h3Get;
};
