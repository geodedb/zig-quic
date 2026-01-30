# Interop Test Certificates

**WARNING: FOR INTEROPERABILITY TESTING ONLY - DO NOT USE IN PRODUCTION**

This directory is for locally generated test certificates used in QUIC interoperability
testing with other implementations (quic-go, aioquic, quinn, etc.). Certificate files
are intentionally excluded from version control.

## Security Warning

Generated certificates are:
- Self-signed with no chain of trust
- NOT suitable for any production use
- Only for testing QUIC protocol compatibility

**DO NOT use these certificates for anything other than local interop testing.**

## Files

| File | Description |
|------|-------------|
| `cert.pem` | EC test certificate (ECDSA P-256) |
| `key.pem` | EC private key |

## Regenerating Certificates

Run the generate script:
```bash
./generate.sh
```

Or manually:
```bash
openssl ecparam -genkey -name prime256v1 -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 365 \
    -subj "/CN=localhost/O=Interop Test/C=US" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:193.167.0.100"
```
