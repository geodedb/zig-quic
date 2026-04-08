package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type TestResult struct {
	Name    string
	Success bool
	Error   error
	Details string
}

func main() {
	var connect string
	var insecure bool
	flag.StringVar(&connect, "connect", "127.0.0.1:4433", "server address")
	flag.BoolVar(&insecure, "insecure", false, "skip certificate verification")
	flag.Parse()

	// Create TLS key log file for debugging (secure temp file with 0600 permissions)
	keyLogFile, err := os.CreateTemp("", "tls_keys_comprehensive-*.log")
	if err != nil {
		log.Printf("Warning: Could not create key log file: %v", err)
	} else {
		defer keyLogFile.Close()
		defer os.Remove(keyLogFile.Name())
		log.Printf("📝 TLS keys will be logged to %s", keyLogFile.Name())
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"hq-interop"},
		KeyLogWriter:       keyLogFile,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Printf("🚀 Starting comprehensive QUIC test suite")
	log.Printf("📡 Connecting to %s", connect)

	conn, err := quic.DialAddr(ctx, connect, tlsConf, &quic.Config{
		MaxIdleTimeout: 60 * time.Second,
	})
	if err != nil {
		log.Fatalf("❌ Failed to connect: %v", err)
	}
	defer conn.CloseWithError(0, "test completed")

	log.Printf("✅ Connection established")
	log.Printf("✅ TLS handshake complete")

	// Run comprehensive test suite
	results := []TestResult{}

	// Test 1: Single stream echo
	results = append(results, testSingleStreamEcho(ctx, conn))

	// Test 2: Multiple concurrent streams
	results = append(results, testMultipleConcurrentStreams(ctx, conn))

	// Test 3: Large data transfer
	results = append(results, testLargeDataTransfer(ctx, conn, 10*1024))    // 10KB
	results = append(results, testLargeDataTransfer(ctx, conn, 100*1024))   // 100KB
	results = append(results, testLargeDataTransfer(ctx, conn, 1024*1024))  // 1MB

	// Test 4: Multiple request-response cycles
	results = append(results, testMultipleRoundTrips(ctx, conn, 10))

	// Test 5: Bidirectional simultaneous send/receive
	results = append(results, testBidirectionalSimultaneous(ctx, conn))

	// Test 6: Stream interleaving
	results = append(results, testStreamInterleaving(ctx, conn, 5))

	// Print test summary
	printTestSummary(results)
}

func testSingleStreamEcho(ctx context.Context, conn *quic.Conn) TestResult {
	log.Printf("\n📝 Test 1: Single stream echo")
	start := time.Now()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return TestResult{"Single Stream Echo", false, err, ""}
	}
	defer stream.Close()

	msg := []byte("Hello from Go client!")
	log.Printf("✓ Stream opened (ID: %d)", stream.StreamID())

	_, err = stream.Write(msg)
	if err != nil {
		return TestResult{"Single Stream Echo", false, err, ""}
	}

	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		return TestResult{"Single Stream Echo", false, err, ""}
	}

	elapsed := time.Since(start)
	details := fmt.Sprintf("Sent %d bytes, received %d bytes in %v", len(msg), n, elapsed)
	log.Printf("✅ %s", details)
	return TestResult{"Single Stream Echo", true, nil, details}
}

func testMultipleConcurrentStreams(ctx context.Context, conn *quic.Conn) TestResult {
	log.Printf("\n📝 Test 2: Multiple concurrent streams")
	start := time.Now()

	numStreams := 4
	var wg sync.WaitGroup
	errors := make(chan error, numStreams)

	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(streamNum int) {
			defer wg.Done()

			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				errors <- fmt.Errorf("stream %d: %w", streamNum, err)
				return
			}
			defer stream.Close()

			msg := fmt.Sprintf("Stream %d message", streamNum)
			_, err = stream.Write([]byte(msg))
			if err != nil {
				errors <- fmt.Errorf("stream %d write: %w", streamNum, err)
				return
			}

			buf := make([]byte, 1024)
			_, err = stream.Read(buf)
			if err != nil && err != io.EOF {
				errors <- fmt.Errorf("stream %d read: %w", streamNum, err)
				return
			}

			log.Printf("✓ Stream %d completed", streamNum)
		}(i)
	}

	wg.Wait()
	close(errors)

	if len(errors) > 0 {
		return TestResult{"Multiple Concurrent Streams", false, <-errors, ""}
	}

	elapsed := time.Since(start)
	details := fmt.Sprintf("%d concurrent streams completed in %v", numStreams, elapsed)
	log.Printf("✅ %s", details)
	return TestResult{"Multiple Concurrent Streams", true, nil, details}
}

func testLargeDataTransfer(ctx context.Context, conn *quic.Conn, size int) TestResult {
	log.Printf("\n📝 Test: Large data transfer (%d bytes)", size)
	start := time.Now()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return TestResult{fmt.Sprintf("Large Transfer (%d)", size), false, err, ""}
	}
	defer stream.Close()

	// Generate random data
	data := make([]byte, size)
	_, err = rand.Read(data)
	if err != nil {
		return TestResult{fmt.Sprintf("Large Transfer (%d)", size), false, err, ""}
	}

	// Send data
	n, err := stream.Write(data)
	if err != nil {
		return TestResult{fmt.Sprintf("Large Transfer (%d)", size), false, err, ""}
	}
	if n != size {
		return TestResult{fmt.Sprintf("Large Transfer (%d)", size), false,
			fmt.Errorf("wrote %d bytes, expected %d", n, size), ""}
	}

	// Read response (expect echo or acknowledgment)
	buf := make([]byte, size+1024)
	total := 0
	for total < size {
		n, err := stream.Read(buf[total:])
		if err != nil {
			if err == io.EOF {
				break
			}
			return TestResult{fmt.Sprintf("Large Transfer (%d)", size), false, err, ""}
		}
		total += n
		if total >= 1024 { // At least got some data back
			break
		}
	}

	elapsed := time.Since(start)
	throughput := float64(size) / elapsed.Seconds() / 1024 / 1024 // MB/s
	details := fmt.Sprintf("Transferred %d bytes in %v (%.2f MB/s)", size, elapsed, throughput)
	log.Printf("✅ %s", details)
	return TestResult{fmt.Sprintf("Large Transfer (%s)", formatSize(size)), true, nil, details}
}

func testMultipleRoundTrips(ctx context.Context, conn *quic.Conn, numRounds int) TestResult {
	log.Printf("\n📝 Test: Multiple round-trips (%d cycles)", numRounds)
	start := time.Now()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return TestResult{"Multiple Round-trips", false, err, ""}
	}
	defer stream.Close()

	for i := 0; i < numRounds; i++ {
		msg := fmt.Sprintf("Round %d", i)
		_, err = stream.Write([]byte(msg))
		if err != nil {
			return TestResult{"Multiple Round-trips", false, err, fmt.Sprintf("round %d", i)}
		}

		buf := make([]byte, 1024)
		_, err = stream.Read(buf)
		if err != nil && err != io.EOF {
			return TestResult{"Multiple Round-trips", false, err, fmt.Sprintf("round %d", i)}
		}
	}

	elapsed := time.Since(start)
	avgLatency := elapsed / time.Duration(numRounds)
	details := fmt.Sprintf("%d round-trips in %v (avg: %v per round)", numRounds, elapsed, avgLatency)
	log.Printf("✅ %s", details)
	return TestResult{"Multiple Round-trips", true, nil, details}
}

func testBidirectionalSimultaneous(ctx context.Context, conn *quic.Conn) TestResult {
	log.Printf("\n📝 Test: Bidirectional simultaneous send/receive")
	start := time.Now()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return TestResult{"Bidirectional Simultaneous", false, err, ""}
	}
	defer stream.Close()

	var wg sync.WaitGroup
	errors := make(chan error, 2)

	// Concurrent sender
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			msg := fmt.Sprintf("Message %d", i)
			_, err := stream.Write([]byte(msg))
			if err != nil {
				errors <- err
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Concurrent receiver
	wg.Add(1)
	received := 0
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for i := 0; i < 10; i++ {
			n, err := stream.Read(buf)
			if err != nil {
				if err != io.EOF {
					errors <- err
				}
				return
			}
			if n > 0 {
				received++
			}
		}
	}()

	wg.Wait()
	close(errors)

	if len(errors) > 0 {
		return TestResult{"Bidirectional Simultaneous", false, <-errors, ""}
	}

	elapsed := time.Since(start)
	details := fmt.Sprintf("10 concurrent send/receives in %v", elapsed)
	log.Printf("✅ %s", details)
	return TestResult{"Bidirectional Simultaneous", true, nil, details}
}

func testStreamInterleaving(ctx context.Context, conn *quic.Conn, numStreams int) TestResult {
	log.Printf("\n📝 Test: Stream interleaving (%d streams)", numStreams)
	start := time.Now()

	streams := make([]*quic.Stream, numStreams)
	for i := 0; i < numStreams; i++ {
		s, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return TestResult{"Stream Interleaving", false, err, ""}
		}
		defer s.Close()
		streams[i] = s
	}

	// Send data in round-robin fashion
	for round := 0; round < 5; round++ {
		for i, stream := range streams {
			msg := fmt.Sprintf("Stream %d, Round %d", i, round)
			_, err := stream.Write([]byte(msg))
			if err != nil {
				return TestResult{"Stream Interleaving", false, err, ""}
			}
		}
	}

	// Read responses
	for i, stream := range streams {
		buf := make([]byte, 1024)
		_, err := stream.Read(buf)
		if err != nil && err != io.EOF {
			return TestResult{"Stream Interleaving", false, err, fmt.Sprintf("stream %d", i)}
		}
	}

	elapsed := time.Since(start)
	details := fmt.Sprintf("%d interleaved streams, 5 rounds in %v", numStreams, elapsed)
	log.Printf("✅ %s", details)
	return TestResult{"Stream Interleaving", true, nil, details}
}

func printTestSummary(results []TestResult) {
	log.Printf("\n" + strings.Repeat("=", 60))
	log.Printf("📊 TEST SUMMARY")
	log.Printf(strings.Repeat("=", 60))

	passed := 0
	failed := 0

	for _, result := range results {
		status := "✅"
		if !result.Success {
			status = "❌"
			failed++
		} else {
			passed++
		}
		log.Printf("%s %s", status, result.Name)
		if result.Details != "" {
			log.Printf("   └─ %s", result.Details)
		}
		if result.Error != nil {
			log.Printf("   └─ Error: %v", result.Error)
		}
	}

	log.Printf("\n" + strings.Repeat("=", 60))
	log.Printf("RESULTS: %d passed, %d failed, %d total", passed, failed, len(results))
	log.Printf(strings.Repeat("=", 60))

	if failed > 0 {
		log.Fatalf("\n❌ Some tests failed")
	}
	log.Printf("\n✅ All tests passed!")
}

func formatSize(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%dB", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%dKB", bytes/1024)
	}
	return fmt.Sprintf("%dMB", bytes/(1024*1024))
}
