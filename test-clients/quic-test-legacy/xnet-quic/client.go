package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"os"
	"time"

	"golang.org/x/net/quic"
)

func main() {
	var connect string
	var insecure bool
	var keyLogPath string
	flag.StringVar(&connect, "connect", "127.0.0.1:4433", "server address")
	flag.BoolVar(&insecure, "insecure", false, "skip certificate verification")
	flag.StringVar(&keyLogPath, "keylog", os.Getenv("SSLKEYLOGFILE"), "write TLS secrets to this file")
	flag.Parse()

	keyLogFile := openKeyLog(keyLogPath)
	if keyLogFile != nil {
		defer keyLogFile.Close()
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: insecure,
		NextProtos:         []string{"hq-interop"},
		KeyLogWriter:       keyLogFile,
		MinVersion:         tls.VersionTLS13,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Printf("🚀 Starting x/net/quic test client")
	log.Printf("📡 Connecting to %s", connect)

	// Create QUIC endpoint by listening on any port
	endpoint, err := quic.Listen("udp", ":0", &quic.Config{
		TLSConfig: tlsConf,
	})
	if err != nil {
		log.Fatalf("❌ Failed to create endpoint: %v", err)
	}
	defer endpoint.Close(ctx)

	log.Printf("✓ Endpoint created, local address: %v", endpoint.LocalAddr())

	// Dial the server
	conn, err := endpoint.Dial(ctx, "udp", connect, &quic.Config{
		TLSConfig: tlsConf,
	})
	if err != nil {
		log.Fatalf("❌ Failed to connect: %v", err)
	}
	defer conn.Abort(nil)

	log.Printf("✅ Connection established")
	log.Printf("✅ TLS handshake complete")

	// Open a bidirectional stream
	stream, err := conn.NewSendOnlyStream(ctx)
	if err != nil {
		log.Fatalf("❌ Failed to create stream: %v", err)
	}

	log.Printf("✓ Stream opened")

	// Send a message
	msg := []byte("Hello from x/net/quic client!")
	n, err := stream.Write(msg)
	if err != nil {
		log.Fatalf("❌ Failed to write: %v", err)
	}
	log.Printf("✓ Sent %d bytes", n)

	// Close the stream to signal we're done sending
	stream.Close()

	log.Printf("✅ Test completed successfully")
}

func openKeyLog(path string) *os.File {
	if path == "" {
		return nil
	}
	keyLogFile, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		log.Printf("Warning: Could not create TLS key log file: %v", err)
		return nil
	}
	log.Printf("TLS keys will be logged to %s", path)
	return keyLogFile
}
