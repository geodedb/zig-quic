package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	var (
		addr     = flag.String("addr", "localhost:4433", "server address")
		insecure = flag.Bool("insecure", true, "skip certificate verification")
		verbose  = flag.Bool("verbose", false, "enable verbose logging")
		message  = flag.String("message", "Hello from Go QUIC client!", "message to send")
	)
	flag.Parse()

	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	}

	// Setup TLS config
	tlsConf := &tls.Config{
		InsecureSkipVerify: *insecure,
		NextProtos:         []string{"quic-zig/1", "h3", "http/0.9"},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	// Setup QUIC config
	quicConfig := &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		InitialStreamReceiveWindow:    512 * 1024,
		InitialConnectionReceiveWindow: 512 * 1024,
		MaxStreamReceiveWindow:        6 * 1024 * 1024,
		MaxConnectionReceiveWindow:    15 * 1024 * 1024,
		KeepAlivePeriod:               10 * time.Second,
		HandshakeIdleTimeout:          10 * time.Second,
		EnableDatagrams:               false,
	}

	log.Printf("Attempting to connect to %s\n", *addr)
	if *verbose {
		log.Printf("TLS Config: InsecureSkipVerify=%v, NextProtos=%v\n", tlsConf.InsecureSkipVerify, tlsConf.NextProtos)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Dial QUIC connection
	conn, err := quic.DialAddr(ctx, *addr, tlsConf, quicConfig)
	if err != nil {
		log.Fatalf("Failed to dial QUIC: %v", err)
	}
	defer conn.CloseWithError(0, "done")

	log.Printf("Successfully connected to %s\n", *addr)

	// Get connection state
	connState := conn.ConnectionState()
	if *verbose {
		log.Printf("TLS Version: %x, Cipher Suite: %x, ALPN: %s\n",
			connState.TLS.Version, connState.TLS.CipherSuite, connState.TLS.NegotiatedProtocol)
	}

	// Open a stream
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatalf("Failed to open stream: %v", err)
	}
	defer stream.Close()

	if *verbose {
		log.Printf("Opened stream %d\n", stream.StreamID())
	}

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
	if *verbose {
		remoteAddr := conn.RemoteAddr()
		localAddr := conn.LocalAddr()
		log.Printf("Local: %v, Remote: %v\n", localAddr, remoteAddr)
	}

	fmt.Println("✓ QUIC connection test successful")
}
