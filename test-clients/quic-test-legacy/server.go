package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"

	"github.com/quic-go/quic-go"
)

func main() {
	addr := "localhost:4242"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	fmt.Printf("quic-go server listening on %s\n", addr)

	conn, err := listener.Accept(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer stream.Close()

	// Echo through the loggingWriter
	_, err = io.Copy(loggingWriter{stream}, stream)
	if err != nil {
		log.Fatal(err)
	}
}

type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Server received: %s\n", string(b))
	// Echo back with "echo: " prefix
	response := fmt.Sprintf("echo: %s", string(b))
	return w.Writer.Write([]byte(response))
}

func generateTLSConfig() *tls.Config {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  priv,
		}},
		NextProtos: []string{"hq-interop"},
	}
}
