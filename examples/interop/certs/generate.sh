#!/usr/bin/env bash
set -euo pipefail

# Generate a self-signed cert for test.local usable for TLS interop testing.
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

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout key.pem -out cert.pem -days "$DAYS" -config openssl.cnf

rm -f openssl.cnf

echo "Wrote cert.pem and key.pem for CN=${CN}"
