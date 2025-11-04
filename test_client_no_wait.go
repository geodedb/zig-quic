package main

import (
	"context"
	"crypto/tls"
	"log"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"hq-interop"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	log.Printf("Connecting to 127.0.0.1:4433")
	conn, err := quic.DialAddr(ctx, "127.0.0.1:4433", tlsConf, &quic.Config{
		MaxIdleTimeout: 10 * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.CloseWithError(0, "client done")

	log.Printf("Connection established!")
	log.Printf("TLS handshake complete")

	// Open a stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Fatalf("Failed to open stream: %v", err)
	}
	log.Printf("Stream opened")

	// Send HTTP/0.9 GET request
	msg := []byte("GET /\r\n")
	_, err = stream.Write(msg)
	if err != nil {
		log.Fatalf("Failed to write: %v", err)
	}
	log.Printf("Sent: %s", msg)

	// Give server time to process
	time.Sleep(2 * time.Second)

	stream.Close()
	log.Printf("Test completed - check server logs for STREAM frame processing")
}
