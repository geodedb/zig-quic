#!/bin/bash

# QC-15: restrict permissions on generated material. openssl writes private keys
# with the process umask, so without this the *.key/*.pem keys would be created
# world-readable. 0077 makes new files owner-only (0600) and new dirs 0700.
umask 077

# Create test certificate directories
mkdir -p tests/certs
mkdir -p tests/certs/valid
mkdir -p tests/certs/self-signed

# Generate root-level certs used by tests if missing
if [ ! -f tests/certs/cert.pem ] || [ ! -f tests/certs/key.pem ]; then
    echo "Creating root test ECDSA certificate (tests/certs/cert.pem)..."
    openssl ecparam -genkey -name prime256v1 -out tests/certs/key.pem
    openssl req -new -x509 -key tests/certs/key.pem -out tests/certs/cert.pem -days 365 \
        -subj "/CN=localhost/O=Test/C=US" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
fi

if [ ! -f tests/certs/server-rsa.crt ] || [ ! -f tests/certs/server-rsa.key ]; then
    echo "Creating root test RSA certificate (tests/certs/server-rsa.crt)..."
    openssl genrsa -out tests/certs/server-rsa.key 2048
    openssl req -new -x509 -key tests/certs/server-rsa.key -out tests/certs/server-rsa.crt -days 365 \
        -subj "/CN=localhost/O=Test/C=US" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
fi

# Function to generate ECDSA P-256 certificate
generate_ecdsa_cert() {
    local dir=$1
    local subject=$2

    # Generate ECDSA private key (P-256)
    openssl ecparam -genkey -name prime256v1 -out "$dir/key.pem"

    # Generate certificate request
    openssl req -new -key "$dir/key.pem" -out "$dir/cert.csr" -subj "$subject"

    # Generate certificate
    openssl x509 -req -in "$dir/cert.csr" -signkey "$dir/key.pem" -out "$dir/cert.pem" -days 365 \
        -extfile <(printf "subjectAltName=DNS:localhost,DNS:127.0.0.1,IP:127.0.0.1\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth")

    # Convert to DER format (binary)
    openssl x509 -in "$dir/cert.pem" -outform DER -out "$dir/cert.der"

    # Clean up CSR
    rm "$dir/cert.csr"

    # Display certificate info
    echo "Certificate created in $dir:"
    openssl x509 -in "$dir/cert.pem" -noout -text | head -20
}

# Function to generate RSA certificate
generate_rsa_cert() {
    local dir=$1
    local subject=$2

    # Generate RSA private key
    openssl genrsa -out "$dir/key_rsa.pem" 2048

    # Generate certificate
    openssl req -new -x509 -key "$dir/key_rsa.pem" -out "$dir/cert_rsa.pem" -days 365 -subj "$subject" \
        -addext "subjectAltName=DNS:localhost,DNS:127.0.0.1,IP:127.0.0.1" \
        -addext "keyUsage=digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth,clientAuth"

    # Convert to DER format
    openssl x509 -in "$dir/cert_rsa.pem" -outform DER -out "$dir/cert_rsa.der"
}

echo "Creating valid test certificates..."
generate_ecdsa_cert "tests/certs/valid" "/CN=quic-test-server/O=QUIC Test/C=US"
generate_rsa_cert "tests/certs/valid" "/CN=quic-test-server-rsa/O=QUIC Test/C=US"

echo "Creating self-signed test certificates..."
generate_ecdsa_cert "tests/certs/self-signed" "/CN=localhost/O=Self-Signed/C=US"
generate_rsa_cert "tests/certs/self-signed" "/CN=localhost-rsa/O=Self-Signed/C=US"

echo "Certificate generation complete!"
echo ""
echo "Files created:"
echo "  Root test certificates:"
echo "    - tests/certs/cert.pem (ECDSA)"
echo "    - tests/certs/key.pem (ECDSA)"
echo "    - tests/certs/server-rsa.crt (RSA)"
echo "    - tests/certs/server-rsa.key (RSA)"
echo "  Valid certificates:"
echo "    - tests/certs/valid/cert.pem (ECDSA)"
echo "    - tests/certs/valid/key.pem (ECDSA)"
echo "    - tests/certs/valid/cert_rsa.pem (RSA)"
echo "    - tests/certs/valid/key_rsa.pem (RSA)"
echo ""
echo "  Self-signed certificates:"
echo "    - tests/certs/self-signed/cert.pem (ECDSA)"
echo "    - tests/certs/self-signed/key.pem (ECDSA)"
echo "    - tests/certs/self-signed/cert_rsa.pem (RSA)"
echo "    - tests/certs/self-signed/key_rsa.pem (RSA)"
