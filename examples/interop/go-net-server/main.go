package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"time"

	"golang.org/x/net/quic"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4434", "listen addr")
	alpn := flag.String("alpn", "h3", "ALPN")
	cert := flag.String("cert", "../certs/cert.pem", "cert path")
	key := flag.String("key", "../certs/key.pem", "key path")
	retry := flag.Bool("retry", false, "require address validation")
	flag.Parse()

	certPair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatalf("load cert: %v", err)
	}
	conf := &tls.Config{Certificates: []tls.Certificate{certPair}, NextProtos: []string{*alpn}}
	qconf := &quic.Config{}
	if *retry {
		qconf.RequireAddressValidation = true
	}

	endpoint, err := quic.Listen("udp", *addr, qconf)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("listening on %s", endpoint.LocalAddr())
	for {
		conn, err := endpoint.Accept(context.Background())
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn)
	}
	_ = conf // keep reference (TLS currently unused until full integration)
}

func handleConn(c *quic.Conn) {
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := c.AcceptStream(ctx)
	if err != nil {
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := st.Read(buf)
		if n > 0 {
			st.Write(buf[:n])
			fmt.Printf("echoed %d bytes\n", n)
		}
		if err != nil {
			return
		}
	}
}
