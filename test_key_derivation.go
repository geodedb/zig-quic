package main

import (
	"crypto"
	_ "crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/hkdf"
)

// hkdfExpandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
func hkdfExpandLabel(hash crypto.Hash, secret, context []byte, label string, length int) []byte {
	b := make([]byte, 3 /* uint16 length, uint8 label length */ +len("tls13 ")+len(label)+1 /* uint8 context length */ +len(context))
	b[0] = uint8(length >> 8)
	b[1] = uint8(length)
	b[2] = uint8(len("tls13 ") + len(label))
	copy(b[3:], "tls13 ")
	copy(b[3+len("tls13 "):], label)
	b[3+len("tls13 ")+len(label)] = uint8(len(context))
	copy(b[3+len("tls13 ")+len(label)+1:], context)

	out := make([]byte, length)
	n, err := hkdf.Expand(hash.New, secret, b).Read(out)
	if err != nil || n != length {
		panic(fmt.Sprintf("hkdf.Expand failed: %v", err))
	}
	return out
}

func main() {
	// Current secret from our logs
	currentSecretHex := "7e1bdecd8d4fe13ff0ffdbf166a1e5314f4638b6ad2f90e942b3e9d7a7e30708"
	currentSecret, err := hex.DecodeString(currentSecretHex)
	if err != nil {
		panic(err)
	}

	// Derive next secret using "quic ku" label
	nextSecret := hkdfExpandLabel(crypto.SHA256, currentSecret, []byte{}, "quic ku", 32)

	fmt.Printf("Current RX secret: %x\n", currentSecret)
	fmt.Printf("Derived NEXT RX secret (quic-go method): %x\n", nextSecret)
	fmt.Println()

	// Our derived secret from the logs
	ourNextSecretHex := "90b4373f77ff6c54d0182d8a4fb12d8fd9ae793dc3a0fe203c0aa78e9a8fbf33"
	ourNextSecret, err := hex.DecodeString(ourNextSecretHex)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Our derived NEXT RX secret: %x\n", ourNextSecret)

	// Compare
	if hex.EncodeToString(nextSecret) == ourNextSecretHex {
		fmt.Println("✅ Secrets MATCH!")
	} else {
		fmt.Println("❌ Secrets DO NOT MATCH!")
		fmt.Printf("Expected: %x\n", nextSecret)
		fmt.Printf("Got:      %x\n", ourNextSecret)
	}
}
