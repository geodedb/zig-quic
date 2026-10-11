package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// Execute the actual command in a child so log.Fatal and flag errors are tested.
func TestClientProcess(t *testing.T) {
	if os.Getenv("QUIC_CLIENT_TEST_PROCESS") != "1" {
		return
	}
	separator := slices.Index(os.Args, "--")
	if separator < 0 {
		t.Fatal("missing client arguments")
	}
	os.Args = append([]string{os.Args[0]}, os.Args[separator+1:]...)
	flag.CommandLine = flag.NewFlagSet("quic-go-test-client", flag.ExitOnError)
	main()
	os.Exit(0)
}

func testCertificate(t *testing.T, wrongHost bool) (tls.Certificate, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "interop fixture CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	if wrongHost {
		leaf.DNSNames = []string{"other.invalid"}
		leaf.IPAddresses = nil
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, caPath
}

func serveFixture(t *testing.T, certificate tls.Certificate, response string) string {
	t.Helper()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate}, NextProtos: []string{"hq-interop"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept(ctx)
		if err != nil {
			return // Untrusted and wrong-host cases intentionally reject the handshake.
		}
		defer connection.CloseWithError(0, "fixture finished")
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			return
		}
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		request, err := io.ReadAll(io.LimitReader(stream, 4096))
		if err != nil || string(request) != "GET /\r\n" {
			return
		}
		_, _ = stream.Write([]byte(response))
		_ = stream.Close()
		<-ctx.Done() // Keep the connection alive until the client has read the FIN.
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		<-done
	})
	return listener.Addr().String()
}

func TestClientCertificateAndResponse(t *testing.T) {
	for _, test := range []struct {
		name      string
		ca        string
		wrongHost bool
		response  string
		wantError string
	}{
		{name: "secure default rejects private CA", response: "fixture-response", wantError: "certificate"},
		{name: "explicit CA verifies handshake and response", ca: "trusted", response: "fixture-response"},
		{name: "unrelated CA is rejected", ca: "unrelated", response: "fixture-response", wantError: "certificate"},
		{name: "trusted CA does not disable hostname verification", ca: "trusted", wrongHost: true, response: "fixture-response", wantError: "certificate"},
		{name: "invalid CA file is rejected", ca: "invalid", response: "fixture-response", wantError: "CA"},
		{name: "empty response is not a successful exchange", ca: "trusted", wantError: "empty response"},
		{name: "oversized response is rejected", ca: "trusted", response: strings.Repeat("x", 4097), wantError: "response exceeds"},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate, caPath := testCertificate(t, test.wrongHost)
			address := serveFixture(t, certificate, test.response)
			args := []string{"-test.run=^TestClientProcess$", "--", "--addr=" + address}
			switch test.ca {
			case "trusted":
				args = append(args, "--ca-file="+caPath)
			case "unrelated":
				_, unrelated := testCertificate(t, false)
				args = append(args, "--ca-file="+unrelated)
			case "invalid":
				invalid := filepath.Join(t.TempDir(), "invalid.pem")
				if err := os.WriteFile(invalid, []byte("not a certificate"), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--ca-file="+invalid)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, args...)
			command.Env = append(os.Environ(), "QUIC_CLIENT_TEST_PROCESS=1", "SSLKEYLOGFILE=")
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("client did not finish: %s", output)
			}
			if strings.Contains(string(output), "flag provided but not defined") {
				t.Fatalf("client rejected the trust option instead of testing TLS: %s", output)
			}
			if test.wantError != "" {
				if err == nil || !strings.Contains(string(output), test.wantError) || strings.Contains(string(output), "Test completed successfully") {
					t.Fatalf("wanted failure containing %q, got %v: %s", test.wantError, err, output)
				}
			} else if err != nil || !strings.Contains(string(output), test.response) || !strings.Contains(string(output), "Test completed successfully") {
				t.Fatalf("verified exchange failed: %v: %s", err, output)
			}
		})
	}
}
