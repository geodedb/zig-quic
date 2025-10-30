package main

import (
    "context"
    "crypto/tls"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "time"

    "github.com/quic-go/quic-go"
    "github.com/quic-go/quic-go/logging"
)

func main() {
    var (
        addr     = flag.String("addr", "localhost:4433", "server address")
        insecure = flag.Bool("insecure", true, "skip certificate verification")
        verbose  = flag.Bool("verbose", false, "enable verbose logging")
        message  = flag.String("message", "Hello from Go QUIC client!", "message to send")
    )
    flag.Parse()

    // Setup TLS config
    tlsConf := &tls.Config{
        InsecureSkipVerify: *insecure,
        NextProtos:         []string{"quic-zig/1", "h3", "http/0.9"},
        MinVersion:         tls.VersionTLS13,
        MaxVersion:         tls.VersionTLS13,
    }

    // Setup QUIC config with detailed logging
    quicConfig := &quic.Config{
        MaxIdleTimeout:          30 * time.Second,
        InitialStreamReceiveWindow:     512 * 1024,
        InitialConnectionReceiveWindow: 512 * 1024,
        MaxStreamReceiveWindow:         6 * 1024 * 1024,
        MaxConnectionReceiveWindow:     15 * 1024 * 1024,
        KeepAlivePeriod:               10 * time.Second,
        HandshakeIdleTimeout:          10 * time.Second,
        EnableDatagrams:               false,
    }

    if *verbose {
        quicConfig.Tracer = func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
            return &logging.ConnectionTracer{
                StartedConnection: func(local, remote net.Addr, srcConnID, destConnID logging.ConnectionID) {
                    log.Printf("Starting connection: local=%v, remote=%v, srcID=%x, destID=%x\n",
                        local, remote, srcConnID, destConnID)
                },
                ClosedConnection: func(err error) {
                    log.Printf("Connection closed: %v\n", err)
                },
                SentTransportParameters: func(params *logging.TransportParameters) {
                    log.Printf("Sent transport parameters: %+v\n", params)
                },
                ReceivedTransportParameters: func(params *logging.TransportParameters) {
                    log.Printf("Received transport parameters: %+v\n", params)
                },
                RestoredTransportParameters: func(params *logging.TransportParameters) {
                    log.Printf("Restored transport parameters: %+v\n", params)
                },
                SentLongHeaderPacket: func(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, ack *logging.AckFrame, frames []logging.Frame) {
                    log.Printf("Sent long header packet: type=%v, version=%x, destConnID=%x, srcConnID=%x, size=%d\n",
                        hdr.Type, hdr.Version, hdr.DestConnectionID, hdr.SrcConnectionID, size)
                    for _, frame := range frames {
                        log.Printf("  Frame: %T %+v\n", frame, frame)
                    }
                },
                SentShortHeaderPacket: func(hdr *logging.ShortHeader, size logging.ByteCount, ecn logging.ECN, ack *logging.AckFrame, frames []logging.Frame) {
                    log.Printf("Sent short header packet: destConnID=%x, size=%d\n", hdr.DestConnectionID, size)
                },
                ReceivedLongHeaderPacket: func(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
                    log.Printf("Received long header packet: type=%v, version=%x, destConnID=%x, srcConnID=%x, size=%d\n",
                        hdr.Type, hdr.Version, hdr.DestConnectionID, hdr.SrcConnectionID, size)
                    for _, frame := range frames {
                        log.Printf("  Frame: %T %+v\n", frame, frame)
                    }
                },
                ReceivedShortHeaderPacket: func(hdr *logging.ShortHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
                    log.Printf("Received short header packet: destConnID=%x, size=%d\n", hdr.DestConnectionID, size)
                },
                ReceivedRetry: func(hdr *logging.Header) {
                    log.Printf("Received retry packet\n")
                },
                ReceivedVersionNegotiationPacket: func(dest, src logging.ArbitraryLenConnectionID, versions []uint32) {
                    log.Printf("Received version negotiation: dest=%x, src=%x, versions=%v\n", dest, src, versions)
                },
                BufferedPacket: func(pt logging.PacketType, size logging.ByteCount) {
                    log.Printf("Buffered packet: type=%v, size=%d\n", pt, size)
                },
                DroppedPacket: func(pt logging.PacketType, pn logging.PacketNumber, size logging.ByteCount, reason logging.PacketDropReason) {
                    log.Printf("Dropped packet: type=%v, pn=%d, size=%d, reason=%v\n", pt, pn, size, reason)
                },
                UpdatedMetrics: func(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
                    if rttStats != nil {
                        log.Printf("Metrics: RTT=%v, CWND=%d, InFlight=%d bytes, %d packets\n",
                            rttStats.SmoothedRTT(), cwnd, bytesInFlight, packetsInFlight)
                    }
                },
                AcknowledgedPacket: func(level logging.EncryptionLevel, pn logging.PacketNumber) {
                    log.Printf("ACK received for packet %d at level %v\n", pn, level)
                },
                LostPacket: func(level logging.EncryptionLevel, pn logging.PacketNumber, reason logging.PacketLossReason) {
                    log.Printf("Lost packet %d at level %v, reason: %v\n", pn, level, reason)
                },
                UpdatedCongestionState: func(state logging.CongestionState) {
                    log.Printf("Congestion state: %v\n", state)
                },
                UpdatedPTOCount: func(value uint32) {
                    log.Printf("PTO count: %d\n", value)
                },
                UpdatedKeyFromTLS: func(level logging.EncryptionLevel, perspective logging.Perspective) {
                    log.Printf("Updated key from TLS: level=%v, perspective=%v\n", level, perspective)
                },
                UpdatedKey: func(phase logging.KeyPhase, remote bool) {
                    log.Printf("Key update: phase=%v, remote=%v\n", phase, remote)
                },
                DroppedEncryptionLevel: func(level logging.EncryptionLevel) {
                    log.Printf("Dropped encryption level: %v\n", level)
                },
                DroppedKey: func(phase logging.KeyPhase) {
                    log.Printf("Dropped key: phase=%v\n", phase)
                },
                SetLossTimer: func(timerType logging.TimerType, level logging.EncryptionLevel, timeout time.Time) {
                    log.Printf("Set loss timer: type=%v, level=%v, timeout=%v\n", timerType, level, timeout)
                },
                LossTimerExpired: func(timerType logging.TimerType, level logging.EncryptionLevel) {
                    log.Printf("Loss timer expired: type=%v, level=%v\n", timerType, level)
                },
                LossTimerCanceled: func() {
                    log.Printf("Loss timer canceled\n")
                },
                ECNStateUpdated: func(state logging.ECNState, trigger logging.ECNStateTrigger) {
                    log.Printf("ECN state updated: state=%v, trigger=%v\n", state, trigger)
                },
                Debug: func(name, msg string) {
                    log.Printf("DEBUG %s: %s\n", name, msg)
                },
                Close: func() {
                    log.Printf("Tracer closed\n")
                },
            }
        }
    }

    // Comment out qlog for now as it has interface issues
    // if *verbose {
    //     quicConfig.Tracer = func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
    //         return qlog.NewConnectionTracer(io.Discard, p, connID)
    //     }
    // }

    log.Printf("Attempting to connect to %s\n", *addr)
    log.Printf("TLS Config: InsecureSkipVerify=%v, NextProtos=%v\n", tlsConf.InsecureSkipVerify, tlsConf.NextProtos)

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Dial QUIC connection
    conn, err := quic.DialAddr(ctx, *addr, tlsConf, quicConfig)
    if err != nil {
        log.Fatalf("Failed to dial QUIC: %v", err)
    }
    defer conn.CloseWithError(0, "done")

    log.Printf("Successfully connected to %s\n", *addr)
    log.Printf("Connection ID: %x\n", conn.LocalAddr())

    // Get connection state
    connState := conn.ConnectionState()
    log.Printf("TLS Version: %x, Cipher Suite: %x, ALPN: %s\n",
        connState.TLS.Version, connState.TLS.CipherSuite, connState.TLS.NegotiatedProtocol)

    // Open a stream
    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        log.Fatalf("Failed to open stream: %v", err)
    }
    defer stream.Close()

    log.Printf("Opened stream %d\n", stream.StreamID())

    // Send message
    _, err = stream.Write([]byte(*message))
    if err != nil {
        log.Fatalf("Failed to write to stream: %v", err)
    }
    log.Printf("Sent message: %s\n", *message)

    // Close write side to signal end of data
    stream.Close()

    // Read response
    buf := make([]byte, 4096)
    n, err := stream.Read(buf)
    if err != nil && err != io.EOF {
        log.Printf("Error reading response: %v", err)
    } else if n > 0 {
        log.Printf("Received response (%d bytes): %s\n", n, string(buf[:n]))
    }

    // Print final stats
    log.Printf("Connection completed successfully")

    // Try to get more detailed info
    remoteAddr := conn.RemoteAddr()
    localAddr := conn.LocalAddr()
    log.Printf("Local: %v, Remote: %v\n", localAddr, remoteAddr)

    fmt.Println("✓ QUIC connection test successful")
}