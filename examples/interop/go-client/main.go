package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
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
	addr := flag.String("addr", "127.0.0.1:4433", "remote addr")
	alpn := flag.String("alpn", "h3", "ALPN")
	sni := flag.String("sni", "test.local", "SNI")
	insecure := flag.Bool("insecure", true, "skip TLS verify (interop/testing)")
	msg := flag.String("msg", "hello", "payload to echo on stream")
	enableDatagram := flag.Bool("datagram", false, "send and expect a datagram echo")
	dmsg := flag.String("dmsg", "ping", "datagram payload")
	versionsFlag := flag.String("versions", "", "comma-separated versions: v1,v2 (order = preference)")
	printVersion := flag.Bool("print-version", false, "print negotiated version")
	flag.Parse()

	tlsConf := &tls.Config{
		ServerName:         *sni,
		InsecureSkipVerify: *insecure,
		NextProtos:         []string{*alpn},
	}
	qconf := &quic.Config{}
	if *enableDatagram {
		qconf.EnableDatagrams = true
	}
	if *versionsFlag != "" {
		vlist, err := parseVersions(*versionsFlag)
		if err != nil {
			log.Fatalf("versions: %v", err)
		}
		qconf.Versions = vlist
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, *addr, tlsConf, qconf)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "bye")

	if *printVersion {
		ver := conn.ConnectionState().Version
		vstr := "unknown"
		switch ver {
		case quic.Version1:
			vstr = "v1"
		case quic.Version2:
			vstr = "v2"
		}
		fmt.Printf("version: %s\n", vstr)
	}

	if *enableDatagram {
		// send datagram and await echo
		if err := conn.SendDatagram([]byte(*dmsg)); err != nil {
			log.Fatalf("send datagram: %v", err)
		}
		dctx, dcancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer dcancel()
		b, err := conn.ReceiveDatagram(dctx)
		if err != nil {
			log.Fatalf("recv datagram: %v", err)
		}
		fmt.Printf("dgram: %s\n", string(b))
	}

	// Stream echo
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Fatalf("open stream: %v", err)
	}
	if _, err := stream.Write([]byte(*msg)); err != nil {
		log.Fatalf("write: %v", err)
	}
	if err := stream.Close(); err != nil {
		log.Printf("stream close: %v", err)
	}
	// Be tolerant of remote connection close after echo: read up to len(msg)
	expected := len(*msg)
	buf := make([]byte, expected)
	n := 0
	readDeadline := time.Now().Add(3 * time.Second)
	_ = stream.SetReadDeadline(readDeadline)
	for n < expected {
		m, rerr := stream.Read(buf[n:])
		if m > 0 {
			n += m
		}
		if rerr != nil {
			if n >= expected {
				break
			}
			log.Fatalf("read: %v", rerr)
		}
	}
	fmt.Printf("echo: %s\n", string(buf[:n]))
}
