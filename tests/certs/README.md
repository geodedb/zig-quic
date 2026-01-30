# Test Certificates

**WARNING: FOR TESTING ONLY - DO NOT USE IN PRODUCTION**

This directory is for locally-generated test certificates used in unit tests,
integration tests, and local development.

**Certificate files are NOT committed to the repository** (blocked by server policy).
You must generate them locally before running tests.

## Required Files

| File | Description | Algorithm |
|------|-------------|-----------|
| `cert.pem` | EC test certificate | ECDSA P-256 |
| `key.pem` | EC private key | ECDSA P-256 |
| `server-rsa.crt` | RSA test certificate | RSA 2048 |
| `server-rsa.key` | RSA private key | RSA 2048 |

## Security Warning

Generated test certificates are:
- Self-signed with no chain of trust
- NOT suitable for any production use
- NOT secure for any real TLS communication

## Generating Test Certificates

If OpenSSL is available, the test suite will auto-generate these files on demand.
You can also generate them manually:

```bash
# One-shot helper
./create_test_certs.sh

# Or generate manually:
# Generate EC P-256 certificate (recommended for testing)
openssl ecparam -genkey -name prime256v1 -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 365 \
    -subj "/CN=localhost/O=Test/C=US" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# Generate RSA certificate
openssl genrsa -out server-rsa.key 2048
openssl req -new -x509 -key server-rsa.key -out server-rsa.crt -days 365 \
    -subj "/CN=localhost/O=Test/C=US" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

## Production Certificates

For production deployments:
1. Obtain certificates from a trusted Certificate Authority (CA)
2. Use proper key management (HSM, secure key storage)
3. Never commit private keys to version control
4. Implement certificate rotation procedures
