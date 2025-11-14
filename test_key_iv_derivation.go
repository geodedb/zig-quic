package main

import (
	"crypto"
	_ "crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/hkdf"
)

func hkdfExpandLabel(hash crypto.Hash, secret, context []byte, label string, length int) []byte {
	b := make([]byte, 3+len("tls13 ")+len(label)+1+len(context))
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
	// From our logs
	currentSecretHex := "55bc142ac532296c46478210d764f696ea8f3d925da83fff73848b5603468b8f"
	currentSecret, _ := hex.DecodeString(currentSecretHex)

	// Derive NEXT secret
	nextSecret := hkdfExpandLabel(crypto.SHA256, currentSecret, []byte{}, "quic ku", 32)
	fmt.Printf("Current RX secret: %x\n", currentSecret)
	fmt.Printf("Derived NEXT RX secret (quic-go): %x\n", nextSecret)
	fmt.Printf("Our derived NEXT secret:          4a4ca912737b406c474c6ca3fe6ce3dc31aee9b5865b7ec788f698b3655f34b1\n\n")

	// Derive key/IV/HP from NEXT secret
	key := hkdfExpandLabel(crypto.SHA256, nextSecret, []byte{}, "quic key", 16)
	iv := hkdfExpandLabel(crypto.SHA256, nextSecret, []byte{}, "quic iv", 12)
	hp := hkdfExpandLabel(crypto.SHA256, nextSecret, []byte{}, "quic hp", 16)

	fmt.Printf("Derived NEXT key (quic-go): %x\n", key)
	fmt.Printf("Our derived NEXT key:       3b56e45fa0f3a232894ae9ad2b4177c5\n\n")

	fmt.Printf("Derived NEXT IV (quic-go): %x\n", iv)
	fmt.Printf("Our derived NEXT IV:       21c8016ddec8faad26220a3d\n\n")

	fmt.Printf("Derived NEXT HP (quic-go): %x\n", hp)
	fmt.Printf("Our derived NEXT HP:       ccc13716fb9c7b186133835ecd2f0bed\n")
}
