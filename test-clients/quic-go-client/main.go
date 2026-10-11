package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	var caPath string
	flag.StringVar(&addr, "addr", "127.0.0.1:4433", "Server address")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&insecure, "insecure", false, "skip certificate verification")
	flag.StringVar(&keyLogPath, "keylog", os.Getenv("SSLKEYLOGFILE"), "write TLS secrets to this file")
	flag.StringVar(&caPath, "ca-file", "", "PEM CA certificates to trust for server verification")
	flag.Parse()

	if verbose {
		os.Setenv("QUIC_GO_LOG_LEVEL", "debug")
	}

	keyLogFile := openKeyLog(keyLogPath)
	if keyLogFile != nil {
		defer keyLogFile.Close()
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: insecure,
		NextProtos:         []string{"hq-interop"},
	}

	// A typed nil *os.File in an io.Writer interface is non-nil and breaks
	// TLS handshakes. Leave KeyLogWriter unset when logging is disabled.
	if keyLogFile != nil {
		tlsConf.KeyLogWriter = keyLogFile
	}
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			log.Fatalf("Failed to read CA file: %v", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			log.Fatal("CA file contains no valid certificates")
		}
		tlsConf.RootCAs = roots
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

	// Require a nonempty, bounded response and its FIN before reporting success.
	deadline, _ := ctx.Deadline()
	if err := stream.SetReadDeadline(deadline); err != nil {
		log.Fatalf("Failed to set response deadline: %v", err)
	}
	response, err := io.ReadAll(io.LimitReader(stream, 4097))
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}
	if len(response) == 0 {
		log.Fatal("empty response is not a successful exchange")
	}
	if len(response) > 4096 {
		log.Fatal("response exceeds 4096 bytes")
	}
	log.Printf("✓ Received response (%d bytes)", len(response))
	fmt.Printf("\n--- Response ---\n%s\n--- End ---\n", response)

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
