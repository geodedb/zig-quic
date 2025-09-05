#!/usr/bin/env bash
set -euo pipefail

# Generate a self-signed ECDSA P-256 cert for test.local (preferred for current TLS impl).
# Requires: openssl

DIR=$(cd "$(dirname "$0")" && pwd)
cd "$DIR"

CN=${CN:-test.local}
DAYS=${DAYS:-3650}

cat > openssl.cnf <<EOF
[req]
default_bits = 2048
distinguished_name = dn
x509_extensions = v3_req
prompt = no

[dn]
CN = ${CN}

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${CN}
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

# Generate EC private key (prime256v1) and self-signed certificate
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -x509 -sha256 -key key.pem -nodes -days "$DAYS" -config openssl.cnf -out cert.pem

rm -f openssl.cnf

echo "Wrote cert.pem and key.pem for CN=${CN}"
