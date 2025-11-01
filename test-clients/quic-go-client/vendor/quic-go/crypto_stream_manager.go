package quic

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

type cryptoStreamManager struct {
	initialStream   *initialCryptoStream
	handshakeStream *cryptoStream
	oneRTTStream    *cryptoStream
}

func newCryptoStreamManager(
	initialStream *initialCryptoStream,
	handshakeStream *cryptoStream,
	oneRTTStream *cryptoStream,
) *cryptoStreamManager {
	return &cryptoStreamManager{
		initialStream:   initialStream,
		handshakeStream: handshakeStream,
		oneRTTStream:    oneRTTStream,
	}
}

func (m *cryptoStreamManager) HandleCryptoFrame(frame *wire.CryptoFrame, encLevel protocol.EncryptionLevel) error {
	//nolint:exhaustive // CRYPTO frames cannot be sent in 0-RTT packets.
	fmt.Printf("[CRYPTO_MGR] Handling CRYPTO frame: enc_level=%s, offset=%d, length=%d\n", encLevel, frame.Offset, len(frame.Data))
	switch encLevel {
	case protocol.EncryptionInitial:
		fmt.Printf("[CRYPTO_MGR] Processing Initial CRYPTO frame\n")
		return m.initialStream.HandleCryptoFrame(frame)
	case protocol.EncryptionHandshake:
		fmt.Printf("[CRYPTO_MGR] Processing Handshake CRYPTO frame\n")
		return m.handshakeStream.HandleCryptoFrame(frame)
	case protocol.Encryption1RTT:
		fmt.Printf("[CRYPTO_MGR] Processing 1-RTT CRYPTO frame\n")
		return m.oneRTTStream.HandleCryptoFrame(frame)
	default:
		return fmt.Errorf("received CRYPTO frame with unexpected encryption level: %s", encLevel)
	}
}

func (m *cryptoStreamManager) GetCryptoData(encLevel protocol.EncryptionLevel) []byte {
	//nolint:exhaustive // CRYPTO frames cannot be sent in 0-RTT packets.
	switch encLevel {
	case protocol.EncryptionInitial:
		fmt.Printf("[CRYPTO_MGR] Processing Initial CRYPTO frame\n")
		return m.initialStream.GetCryptoData()
	case protocol.EncryptionHandshake:
		fmt.Printf("[CRYPTO_MGR] Processing Handshake CRYPTO frame\n")
		return m.handshakeStream.GetCryptoData()
	case protocol.Encryption1RTT:
		fmt.Printf("[CRYPTO_MGR] Processing 1-RTT CRYPTO frame\n")
		return m.oneRTTStream.GetCryptoData()
	default:
		panic(fmt.Sprintf("received CRYPTO frame with unexpected encryption level: %s", encLevel))
	}
}

func (m *cryptoStreamManager) GetPostHandshakeData(maxSize protocol.ByteCount) *wire.CryptoFrame {
	if !m.oneRTTStream.HasData() {
		return nil
	}
	return m.oneRTTStream.PopCryptoFrame(maxSize)
}

func (m *cryptoStreamManager) Drop(encLevel protocol.EncryptionLevel) error {
	//nolint:exhaustive // 1-RTT keys should never get dropped.
	switch encLevel {
	case protocol.EncryptionInitial:
		fmt.Printf("[CRYPTO_MGR] Processing Initial CRYPTO frame\n")
		return m.initialStream.Finish()
	case protocol.EncryptionHandshake:
		fmt.Printf("[CRYPTO_MGR] Processing Handshake CRYPTO frame\n")
		return m.handshakeStream.Finish()
	default:
		panic(fmt.Sprintf("dropped unexpected encryption level: %s", encLevel))
	}
}
