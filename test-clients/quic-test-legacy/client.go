package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/quic-go/quic-go"
)

func main() {
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	flag.Parse()
	args := flag.Args()
	if len(args) < 2 {
		fmt.Printf("Usage: %s <server-address> <message>\n", os.Args[0])
		fmt.Printf("Example: %s -insecure localhost:4242 hello\n", os.Args[0])
		os.Exit(1)
	}

	addr := args[0]
	message := args[1]

	tlsConf := &tls.Config{
		InsecureSkipVerify: *insecure,
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
