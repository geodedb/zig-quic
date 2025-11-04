package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
)

type diagnosticTracer struct{}

func (t *diagnosticTracer) TracerForConnection(ctx context.Context, p logging.Perspective, odcid logging.ConnectionID) logging.ConnectionTracer {
	return &diagConnTracer{}
}

func (t *diagnosticTracer) SentPacket(addr interface{}, hdr *logging.Header, size logging.ByteCount, frames []logging.Frame) {
	fmt.Printf("[QUIC-GO] Sent packet: size=%d, pn=%d, frames=%d\n", size, hdr.PacketNumber, len(frames))
}

func (t *diagnosticTracer) SentVersionNegotiationPacket(addr interface{}, src, dest logging.ArbitraryLenConnectionID, versions []logging.VersionNumber) {
}

func (t *diagnosticTracer) DroppedPacket(addr interface{}, typ logging.PacketType, size logging.ByteCount, reason logging.PacketDropReason) {
	fmt.Printf("[QUIC-GO] Dropped packet: typ=%v, size=%d, reason=%v\n", typ, size, reason)
}

type diagConnTracer struct{}

func (t *diagConnTracer) StartedConnection(local, remote interface{}, srcConnID, destConnID logging.ConnectionID) {
	fmt.Printf("[CONN] Started connection: local=%v, remote=%v\n", local, remote)
}

func (t *diagConnTracer) NegotiatedVersion(chosen logging.VersionNumber, clientVersions, serverVersions []logging.VersionNumber) {
	fmt.Printf("[CONN] Negotiated version: %#x\n", chosen)
}

func (t *diagConnTracer) ClosedConnection(err error) {
	fmt.Printf("[CONN] Connection closed: %v\n", err)
}

func (t *diagConnTracer) SentTransportParameters(params *logging.TransportParameters) {
	fmt.Printf("[CONN] Sent transport params\n")
}

func (t *diagConnTracer) ReceivedTransportParameters(params *logging.TransportParameters) {
	fmt.Printf("[CONN] Received transport params\n")
}

func (t *diagConnTracer) RestoredTransportParameters(params *logging.TransportParameters) {}

func (t *diagConnTracer) SentLongHeaderPacket(hdr *logging.ExtendedHeader, size logging.ByteCount, ack *logging.AckFrame, frames []logging.Frame) {
	fmt.Printf("[CONN] Sent long header packet: pn=%d, size=%d\n", hdr.PacketNumber, size)
}

func (t *diagConnTracer) SentShortHeaderPacket(hdr *logging.ShortHeader, size logging.ByteCount, ack *logging.AckFrame, frames []logging.Frame) {
	fmt.Printf("[CONN] Sent 1-RTT packet: pn=%d, size=%d, frames=%d\n", hdr.PacketNumber, size, len(frames))
	for i, frame := range frames {
		fmt.Printf("    Frame[%d]: %T\n", i, frame)
		if sf, ok := frame.(*logging.StreamFrame); ok {
			fmt.Printf("      STREAM id=%d, offset=%d, len=%d, fin=%v\n", sf.StreamID, sf.Offset, sf.Length, sf.Fin)
		}
	}
}

func (t *diagConnTracer) ReceivedVersionNegotiationPacket(dest, src logging.ArbitraryLenConnectionID, versions []logging.VersionNumber) {
}

func (t *diagConnTracer) ReceivedRetry(hdr *logging.Header) {}

func (t *diagConnTracer) ReceivedLongHeaderPacket(hdr *logging.ExtendedHeader, size logging.ByteCount, frames []logging.Frame) {
	fmt.Printf("[CONN] Received long header packet: pn=%d, size=%d\n", hdr.PacketNumber, size)
}

func (t *diagConnTracer) ReceivedShortHeaderPacket(hdr *logging.ShortHeader, size logging.ByteCount, frames []logging.Frame) {
	fmt.Printf("[CONN] Received 1-RTT packet: pn=%d, size=%d, frames=%d\n", hdr.PacketNumber, size, len(frames))
	for i, frame := range frames {
		fmt.Printf("    Frame[%d]: %T\n", i, frame)
		if sf, ok := frame.(*logging.StreamFrame); ok {
			fmt.Printf("      STREAM id=%d, offset=%d, len=%d, fin=%v\n", sf.StreamID, sf.Offset, sf.Length, sf.Fin)
		}
	}
}

func (t *diagConnTracer) BufferedPacket(typ logging.PacketType, size logging.ByteCount) {}

func (t *diagConnTracer) DroppedPacket(typ logging.PacketType, pn logging.PacketNumber, size logging.ByteCount, reason logging.PacketDropReason) {
	fmt.Printf("[CONN] Dropped packet: typ=%v, pn=%d, size=%d, reason=%v\n", typ, pn, size, reason)
}

func (t *diagConnTracer) UpdatedMetrics(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
}

func (t *diagConnTracer) AcknowledgedPacket(encLevel logging.EncryptionLevel, pn logging.PacketNumber) {
	fmt.Printf("[CONN] ACK received for packet: level=%v, pn=%d\n", encLevel, pn)
}

func (t *diagConnTracer) LostPacket(encLevel logging.EncryptionLevel, pn logging.PacketNumber, reason logging.PacketLossReason) {
	fmt.Printf("[CONN] Packet lost: level=%v, pn=%d, reason=%v\n", encLevel, pn, reason)
}

func (t *diagConnTracer) UpdatedCongestionState(state logging.CongestionState) {}

func (t *diagConnTracer) UpdatedPTOCount(value uint32) {}

func (t *diagConnTracer) UpdatedKeyFromTLS(encLevel logging.EncryptionLevel, perspective logging.Perspective) {
	fmt.Printf("[CONN] Updated keys: level=%v, perspective=%v\n", encLevel, perspective)
}

func (t *diagConnTracer) UpdatedKey(keyPhase logging.KeyPhaseNumber, remote bool) {
	fmt.Printf("[CONN] Key update: phase=%d, remote=%v\n", keyPhase, remote)
}

func (t *diagConnTracer) DroppedEncryptionLevel(encLevel logging.EncryptionLevel) {
	fmt.Printf("[CONN] Dropped encryption level: %v\n", encLevel)
}

func (t *diagConnTracer) DroppedKey(keyPhase logging.KeyPhaseNumber) {}

func (t *diagConnTracer) SetLossTimer(timerType logging.TimerType, encLevel logging.EncryptionLevel, timeout time.Time) {
}

func (t *diagConnTracer) LossTimerExpired(timerType logging.TimerType, encLevel logging.EncryptionLevel) {}

func (t *diagConnTracer) LossTimerCanceled() {}

func (t *diagConnTracer) Close() {}

func (t *diagConnTracer) Debug(name, msg string) {
	fmt.Printf("[DEBUG] %s: %s\n", name, msg)
}

func main() {
	fmt.Println("\n=== DIAGNOSTIC QUIC-GO CLIENT ===")
	fmt.Println("Purpose: Debug 1-RTT bi-directional communication with Zig server")
	fmt.Println("Expected: Send STREAM data, receive echo response\n")

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"hq-interop"},
	}

	quicConf := &quic.Config{
		Tracer: qlog.DefaultTracer,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println(">>> Dialing 127.0.0.1:4433...")
	conn, err := quic.DialAddr(ctx, "127.0.0.1:4433", tlsConf, quicConf)
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	fmt.Println(">>> Connection established!")
	fmt.Println()

	fmt.Println(">>> Opening stream...")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Fatalf("Failed to open stream: %v", err)
	}
	defer stream.Close()

	fmt.Printf(">>> Opened stream ID: %d\n", stream.StreamID())
	fmt.Println()

	// Send test data
	message := []byte("GET /\r\n")
	fmt.Printf(">>> Sending %d bytes: %q\n", len(message), message)

	n, err := stream.Write(message)
	if err != nil {
		log.Fatalf("Failed to write: %v", err)
	}
	fmt.Printf(">>> Write() returned: %d bytes written\n", n)
	fmt.Println()

	// Try to read response
	fmt.Println(">>> Reading response (timeout 5s)...")
	buf := make([]byte, 4096)

	// Set read deadline
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))

	nr, err := stream.Read(buf)
	if err != nil {
		if err == io.EOF {
			fmt.Println(">>> Got EOF (stream closed by server)")
		} else {
			fmt.Printf(">>> Read error: %v\n", err)
		}
	}

	if nr > 0 {
		fmt.Printf(">>> SUCCESS! Received %d bytes:\n", nr)
		fmt.Printf("    Data: %q\n", buf[:nr])
		fmt.Printf("    Hex:  ")
		for _, b := range buf[:nr] {
			fmt.Printf("%02x ", b)
		}
		fmt.Println()
	} else {
		fmt.Println(">>> FAILURE: No data received from server")
	}

	fmt.Println()
	fmt.Println("=== Test Complete ===")
}
