#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Generate a server leaf and a distinct trust anchor for verified interop tests.
set -euo pipefail
umask 077

if [[ $# -gt 1 ]]; then
    echo "usage: $0 [output-directory]" >&2
    exit 2
fi
cert_dir="${1:-tests/certs/external}"
mkdir -p -- "$cert_dir"
cert_dir="$(cd -- "$cert_dir" && pwd)"
temporary="$(mktemp -d "$cert_dir/.interop.XXXXXX")"
trap 'rm -rf -- "$temporary"' EXIT

openssl ecparam -genkey -name prime256v1 -out "$temporary/ca-key.pem"
openssl req -new -x509 -key "$temporary/ca-key.pem" -out "$temporary/ca.pem" \
    -days 365 -sha256 -subj "/CN=QUIC interop test CA/O=Test" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl ecparam -genkey -name prime256v1 -out "$temporary/key.pem"
openssl req -new -key "$temporary/key.pem" -out "$temporary/server.csr" \
    -subj "/CN=localhost/O=Test"
printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature' \
    'extendedKeyUsage=serverAuth' \
    'subjectAltName=DNS:localhost,DNS:server,DNS:server4,DNS:server6,DNS:server46,IP:127.0.0.1,IP:::1' > "$temporary/server.ext"
openssl x509 -req -in "$temporary/server.csr" -CA "$temporary/ca.pem" \
    -CAkey "$temporary/ca-key.pem" -CAcreateserial -out "$temporary/cert.pem" \
    -days 365 -sha256 -extfile "$temporary/server.ext"
for hostname in localhost server server4 server6 server46; do
    openssl verify -CAfile "$temporary/ca.pem" -purpose sslserver \
        -verify_hostname "$hostname" "$temporary/cert.pem"
done
openssl verify -CAfile "$temporary/ca.pem" -purpose sslserver \
    -verify_ip 127.0.0.1 "$temporary/cert.pem"

# Only the server key survives; the temporary CA signing key is removed by trap.
mv -f -- "$temporary/ca.pem" "$cert_dir/ca.pem"
mv -f -- "$temporary/cert.pem" "$cert_dir/cert.pem"
mv -f -- "$temporary/key.pem" "$cert_dir/key.pem"
