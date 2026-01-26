package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	var addr string
	var verbose bool
	flag.StringVar(&addr, "addr", "127.0.0.1:4433", "Server address")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.Parse()

	if verbose {
		os.Setenv("QUIC_GO_LOG_LEVEL", "debug")
	}

	// TLS config with insecure verification for testing
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"hq-interop"},
	}

	// QUIC config
	quicConf := &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	}

	log.Printf("Connecting to %s with ALPN: hq-interop", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, tlsConf, quicConf)
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	log.Printf("✓ Connection established (handshake complete)")

	// Open a stream and send a simple HTTP/0.9 request
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Fatalf("Failed to open stream: %v", err)
	}
	defer stream.Close()

	log.Printf("✓ Stream opened (ID: %d)", stream.StreamID())

	// Send HTTP/0.9 request
	request := "GET /\r\n"
	_, err = stream.Write([]byte(request))
	if err != nil {
		log.Fatalf("Failed to write request: %v", err)
	}
	stream.Close()
	log.Printf("✓ Sent request: %q", request)

	// Read response
	response := make([]byte, 4096)
	n, err := stream.Read(response)
	if err != nil && err != io.EOF {
		log.Fatalf("Failed to read response: %v", err)
	}

	log.Printf("✓ Received response (%d bytes)", n)
	if n > 0 {
		fmt.Printf("\n--- Response ---\n%s\n--- End ---\n", response[:n])
	}

	log.Printf("✓ Test completed successfully!")
}
