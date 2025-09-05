package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	var connect string
	var insecure bool
	flag.StringVar(&connect, "connect", "127.0.0.1:4433", "server address")
	flag.BoolVar(&insecure, "insecure", false, "skip certificate verification")
	flag.Parse()

	tlsConf := &tls.Config{
		InsecureSkipVerify: insecure,
		NextProtos:         []string{"h3"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

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

	// Send some data
	msg := []byte("Hello from Go client!")
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