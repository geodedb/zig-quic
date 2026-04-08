package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	var connect string
	var insecure bool
	flag.StringVar(&connect, "connect", "127.0.0.1:4433", "server address")
	flag.BoolVar(&insecure, "insecure", false, "skip certificate verification")
	flag.Parse()

	// Create TLS key log file for debugging (secure temp file with 0600 permissions)
	keyLogFile, err := os.CreateTemp("", "tls_keys-*.log")
	if err != nil {
		log.Printf("Warning: Could not create key log file: %v", err)
	} else {
		defer os.Remove(keyLogFile.Name())
		log.Printf("TLS keys will be logged to %s", keyLogFile.Name())
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,  // Always use insecure for testing
		NextProtos:         []string{"hq-interop"},
		KeyLogWriter:       keyLogFile,  // Export TLS secrets for debugging
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if keyLogFile != nil {
		defer keyLogFile.Close()
	}

	log.Printf("Connecting to %s", connect)
	conn, err := quic.DialAddr(ctx, connect, tlsConf, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	log.Printf("Connected successfully!")
	
	// Open a stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Fatalf("Failed to open stream: %v", err)
	}
	defer stream.Close()

	// Send some data (matching what we're debugging)
	msg := []byte("GET /\r\n")
	_, err = stream.Write(msg)
	if err != nil {
		log.Fatalf("Failed to write: %v", err)
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil {
		log.Printf("Read error: %v", err)
	} else {
		log.Printf("Received: %s", buf[:n])
	}

	fmt.Println("Test completed successfully")
}