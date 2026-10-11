#!/usr/bin/env bash
# Prepare private endpoint credentials after dropping privileges. Mounted
# credentials arrive on read-only descriptors opened by the entrypoint.
set -euo pipefail
umask 077

[[ "$(id -un)" == quic ]] || { echo "TLS preparation requires quic" >&2; exit 126; }
cert_dir=/quic/certs
mkdir -p "$cert_dir"
chmod 700 "$cert_dir"
temporary=$(mktemp -d "$cert_dir/.tls.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT

case "${1:-}" in
  mounted)
    cat <&3 > "$temporary/cert.pem"
    cat <&4 > "$temporary/key.pem"
    ;;
  fallback)
    days="${QNS_FALLBACK_CERT_DAYS:-1}"
    [[ "$days" =~ ^[1-9][0-9]*$ ]] || { echo "Invalid certificate lifetime" >&2; exit 2; }
    openssl ecparam -genkey -name prime256v1 -out "$temporary/key.pem"
    openssl req -new -x509 -sha256 -key "$temporary/key.pem" \
      -out "$temporary/cert.pem" -days "$days" -subj /CN=server \
      -addext 'subjectAltName=DNS:server,DNS:server4,DNS:server6,DNS:server46,DNS:localhost,IP:127.0.0.1,IP:::1' \
      -addext 'keyUsage=critical,digitalSignature' \
      -addext 'basicConstraints=critical,CA:FALSE' \
      -addext 'extendedKeyUsage=serverAuth'
    ;;
  *) echo "Expected mounted or fallback TLS material" >&2; exit 2 ;;
esac

# Fail before starting the endpoint if the material is malformed or mismatched.
openssl x509 -in "$temporary/cert.pem" -pubkey -noout > "$temporary/cert.pub"
openssl pkey -in "$temporary/key.pem" -pubout > "$temporary/key.pub"
cmp "$temporary/cert.pub" "$temporary/key.pub"
chmod 600 "$temporary/cert.pem" "$temporary/key.pem"
mv -f "$temporary/cert.pem" "$cert_dir/cert.pem"
mv -f "$temporary/key.pem" "$cert_dir/key.pem"
