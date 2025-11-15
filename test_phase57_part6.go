package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	// Configure TLS to skip verification (testing only)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"hq-interop"},
	}

	// Connect to server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, "127.0.0.1:4433", tlsConf, nil)
	if err != nil {
		log.Fatalf("❌ Failed to connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	fmt.Println("✅ Connected to server")

	// Test 1: Single echo
	fmt.Println("\n📝 Test 1: Single stream echo (19 bytes)")
	if err := testEcho(conn, "Hello from Go!", 1); err != nil {
		fmt.Printf("❌ Test 1 FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Test 1 PASSED")

	// Test 2: 10KB transfer
	fmt.Println("\n📝 Test 2: Large transfer (10240 bytes)")
	data10k := make([]byte, 10240)
	for i := range data10k {
		data10k[i] = byte(i % 256)
	}
	if err := testEcho(conn, string(data10k), 1); err != nil {
		fmt.Printf("❌ Test 2 FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Test 2 PASSED")

	// Test 3: 100KB transfer (THE CRITICAL TEST)
	fmt.Println("\n📝 Test 3: Large transfer (102400 bytes) - CRITICAL TEST")
	data100k := make([]byte, 102400)
	for i := range data100k {
		data100k[i] = byte(i % 256)
	}
	if err := testEcho(conn, string(data100k), 1); err != nil {
		fmt.Printf("❌ Test 3 FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Test 3 PASSED - Phase 57 Part 6 fix verified!")

	fmt.Println("\n============================================================")
	fmt.Println("✅ ALL TESTS PASSED")
	fmt.Println("============================================================")
}

func testEcho(conn quic.Connection, data string, timeoutSec int) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	// Open stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	// Send data
	n, err := stream.Write([]byte(data))
	if err != nil {
		return fmt.Errorf("write failed: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("short write: %d/%d", n, len(data))
	}

	// Close write side to signal FIN
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close failed: %w", err)
	}

	// Read echo
	buf := make([]byte, len(data)+1024)
	totalRead := 0
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)

	for totalRead < len(data) {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout: read %d/%d bytes", totalRead, len(data))
		}

		stream.SetReadDeadline(deadline)
		n, err := stream.Read(buf[totalRead:])
		totalRead += n

		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read failed after %d bytes: %w", totalRead, err)
		}
	}

	if totalRead != len(data) {
		return fmt.Errorf("echo mismatch: sent %d, received %d", len(data), totalRead)
	}

	fmt.Printf("   Sent %d bytes, received %d bytes\n", len(data), totalRead)
	return nil
}
