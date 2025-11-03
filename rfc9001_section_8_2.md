# RFC 9001 Section 8.2 - QUIC Transport Parameters Extension

## Key Requirements

From RFC 9001 §8.2:

> **The quic_transport_parameters extension is carried in the ClientHello and the EncryptedExtensions messages during the handshake.**

> Endpoints MUST send the quic_transport_parameters extension; endpoints that receive ClientHello or EncryptedExtensions messages without the quic_transport_parameters extension MUST close the connection with an error of type 0x16d (equivalent to a fatal TLS missing_extension alert, see Section 4.8).

## Critical Points

1. **ClientHello**: Client MUST include quic_transport_parameters extension (0x0039)
2. **EncryptedExtensions**: Server MUST include quic_transport_parameters extension (0x0039)
3. **ServerHello**: Server MUST NOT include quic_transport_parameters

## Why This Matters

The ServerHello in TLS 1.3 has a very specific structure per RFC 8446:

- ServerHello extensions are limited to:
  - supported_versions (mandatory for TLS 1.3)
  - key_share (for ECDHE)
  - pre_shared_key (for PSK resumption)

All other server parameters (ALPN, transport parameters, etc.) go in EncryptedExtensions.

## Comparison with TLS 1.2

In TLS 1.2, server extensions went in ServerHello.
In TLS 1.3, they go in EncryptedExtensions.

This is a fundamental change to prevent passive observers from seeing negotiated parameters.
