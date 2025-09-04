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
	addr := flag.String("addr", "127.0.0.1:4434", "remote addr")
	alpn := flag.String("alpn", "h3", "ALPN")
	sni := flag.String("sni", "test.local", "SNI")
	insecure := flag.Bool("insecure", true, "skip TLS verify")
	msg := flag.String("msg", "hello", "echo payload")
	flag.Parse()

	tlsConf := &tls.Config{ServerName: *sni, InsecureSkipVerify: *insecure, NextProtos: []string{*alpn}}
	qconf := &quic.Config{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	endpoint, err := quic.Listen("udp", "0.0.0.0:0", nil)
	if err != nil { log.Fatalf("listen: %v", err) }
	conn, err := endpoint.Dial(ctx, "udp", *addr, qconf)
	if err != nil { log.Fatalf("dial: %v", err) }
	defer conn.Close()
	st, err := conn.NewStream(ctx)
	if err != nil { log.Fatalf("new stream: %v", err) }
	if _, err := st.Write([]byte(*msg)); err != nil { log.Fatalf("write: %v", err) }
	st.Flush()
	st.CloseWrite()
	buf := make([]byte, len(*msg))
	_, _ = st.Read(buf)
	fmt.Printf("echo: %s\n", string(buf))
	_ = tlsConf // not yet wired in (quic Listen/Dial placeholder usage)
}
