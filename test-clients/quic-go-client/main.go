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
	var insecure bool
	var keyLogPath string
	flag.StringVar(&addr, "addr", "127.0.0.1:4433", "Server address")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&insecure, "insecure", false, "skip certificate verification")
	flag.StringVar(&keyLogPath, "keylog", os.Getenv("SSLKEYLOGFILE"), "write TLS secrets to this file")
	flag.Parse()

	if verbose {
		os.Setenv("QUIC_GO_LOG_LEVEL", "debug")
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: insecure,
		NextProtos:         []string{"hq-interop"},
	}

	// Only set KeyLogWriter when a file was opened. Assigning a nil *os.File
	// to the io.Writer field yields a non-nil interface whose Write returns
	// os.ErrInvalid, which crypto/tls surfaces as a fatal handshake error
	// ("CRYPTO_ERROR 0x150 (local): tls: KeyLogWriter: invalid argument").
	if keyLogFile := openKeyLog(keyLogPath); keyLogFile != nil {
		defer keyLogFile.Close()
		tlsConf.KeyLogWriter = keyLogFile
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
