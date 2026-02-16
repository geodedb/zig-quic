package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/quic-go/quic-go"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <server-address> <message>\n", os.Args[0])
		fmt.Printf("Example: %s localhost:4242 hello\n", os.Args[0])
		os.Exit(1)
	}

	addr := os.Args[1]
	message := os.Args[2]

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"hq-interop"},
	}

	quicConf := &quic.Config{
		EnableDatagrams: false,
	}

	log.Printf("Connecting to %s", addr)
	conn, err := quic.DialAddr(context.Background(), addr, tlsConf, quicConf)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer stream.Close()

	// Send message
	if _, err := stream.Write([]byte(message)); err != nil {
		log.Fatal(err)
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		log.Fatal(err)
	}

	response := string(buf[:n])
	fmt.Printf("%s\n", response)
}
