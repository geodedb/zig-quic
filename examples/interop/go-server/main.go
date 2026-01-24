package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"
)

func parseVersions(s string) ([]quic.Version, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]quic.Version, 0, len(parts))
	for _, p := range parts {
		switch strings.TrimSpace(p) {
		case "v1":
			out = append(out, quic.Version1)
		case "v2":
			out = append(out, quic.Version2)
		default:
			return nil, fmt.Errorf("unknown version: %s", p)
		}
	}
	return out, nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:4433", "listen addr")
	alpn := flag.String("alpn", "h3", "ALPN")
	cert := flag.String("cert", "../certs/cert.pem", "cert path")
	key := flag.String("key", "../certs/key.pem", "key path")
	retry := flag.Bool("retry", false, "force Retry (address validation)")
	datagram := flag.Bool("datagram", false, "enable DATAGRAM and echo")
	versionsFlag := flag.String("versions", "", "comma-separated versions to support: v1,v2 (order = preference)")
	flag.Parse()

	certPair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatalf("load cert: %v", err)
	}
	conf := &tls.Config{
		Certificates: []tls.Certificate{certPair},
		NextProtos:   []string{*alpn},
	}
	qconf := &quic.Config{}
	if *datagram {
		qconf.EnableDatagrams = true
	}
	if *versionsFlag != "" {
		vlist, err := parseVersions(*versionsFlag)
		if err != nil {
			log.Fatalf("versions: %v", err)
		}
		qconf.Versions = vlist
	}

	// Manually create a UDP socket so we can enable Retry via Transport.VerifySourceAddress
	udpAddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatalf("resolve: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("listen udp: %v", err)
	}
	tr := &quic.Transport{Conn: udpConn}
	if *retry {
		tr.VerifySourceAddress = func(net.Addr) bool { return true }
	}
	ln, err := tr.Listen(conf, qconf)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	la := udpConn.LocalAddr()
	if la != nil {
		log.Printf("listening on %s", la.String())
	} else {
		log.Printf("listening on %s", *addr)
	}
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			log.Printf("accept err: %v", err)
			continue
		}
		go handleConn(conn, *datagram)
	}
}

func handleConn(conn quic.Connection, dgram bool) {
	defer conn.CloseWithError(0, "bye")
	// If datagrams enabled, echo them
	if dgram {
		go func() {
			for {
				b, err := conn.ReceiveDatagram(context.Background())
				if err != nil {
					return
				}
				_ = conn.SendDatagram(b)
			}
		}()
	}
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("accept stream: %v", err)
		return
	}
	n := 0
	buf := make([]byte, 4096)
	for {
		_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
		m, err := stream.Read(buf)
		if err != nil {
			return
		}
		n += m
		_, _ = stream.Write(buf[:m])
		if n > 0 {
			fmt.Printf("echoed %d bytes\n", n)
		}
	}
}
