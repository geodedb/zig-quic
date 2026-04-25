#!/usr/bin/env bash

prepare_local_interop_assets() {
    local root="${1:-$(cd -- "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
    local cert_dir="${root}/examples/interop/quic-interop-runner/certs"
    local www_dir="${root}/examples/interop/quic-network-simulator/www"
    local logs_dir="${root}/examples/interop/quic-network-simulator/logs"
    local test_probe
    local ca_pem_source="${root}/tests/certs/ca.pem"

    mkdir -p "${cert_dir}" "${www_dir}" "${logs_dir}/server/qlog" "${logs_dir}/client/qlog" "${logs_dir}/sim"

    # Local Docker runs can leave these directories root-owned.
    test_probe="${www_dir}/.write-test.$$"
    if ! touch "${test_probe}" 2>/dev/null; then
        if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            sudo chown -R "$(id -u):$(id -g)" \
                "${root}/examples/interop/quic-network-simulator" \
                "${root}/examples/interop/quic-interop-runner" || true
            touch "${test_probe}" 2>/dev/null || true
        fi
    fi
    rm -f "${test_probe}" 2>/dev/null || true

    # Build an interop CA + server leaf pair so strict clients can validate a
    # proper trust chain. Fall back to static test certs if openssl is absent.
    if command -v openssl >/dev/null 2>&1; then
        local cert_tmp
        cert_tmp="$(mktemp -d "${TMPDIR:-/tmp}/qns-certs.XXXXXX")"
        (
            set -euo pipefail

            openssl ecparam -name prime256v1 -genkey -noout -out "${cert_tmp}/ca.key"
            cat > "${cert_tmp}/ca.cnf" <<'EOF'
[req]
distinguished_name=dn
x509_extensions=v3_ca
prompt=no
[dn]
CN=zig-quic-interop-ca
O=zig-quic interop
[v3_ca]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
authorityKeyIdentifier=keyid:always
subjectKeyIdentifier=hash
EOF
            openssl req -x509 -new -key "${cert_tmp}/ca.key" -sha256 -days 3650 -out "${cert_tmp}/ca.pem" -config "${cert_tmp}/ca.cnf"

            openssl ecparam -name prime256v1 -genkey -noout -out "${cert_tmp}/server.key"
            cat > "${cert_tmp}/server.cnf" <<'EOF'
[req]
distinguished_name=dn
req_extensions=v3_req
prompt=no
[dn]
CN=server
O=zig-quic interop
[v3_req]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt
[alt]
DNS.1=server
DNS.2=server4
DNS.3=server6
DNS.4=server46
EOF
            openssl req -new -key "${cert_tmp}/server.key" -out "${cert_tmp}/server.csr" -config "${cert_tmp}/server.cnf"
            openssl x509 -req \
                -in "${cert_tmp}/server.csr" \
                -CA "${cert_tmp}/ca.pem" \
                -CAkey "${cert_tmp}/ca.key" \
                -CAcreateserial \
                -out "${cert_tmp}/server.crt" \
                -days 3650 \
                -sha256 \
                -extensions v3_req \
                -extfile "${cert_tmp}/server.cnf"
        ) || true

        if [[ -s "${cert_tmp}/server.crt" && -s "${cert_tmp}/server.key" && -s "${cert_tmp}/ca.pem" ]]; then
            install -m 0644 "${cert_tmp}/server.crt" "${cert_dir}/cert.pem"
            install -m 0644 "${cert_tmp}/server.key" "${cert_dir}/key.pem"
            install -m 0644 "${cert_tmp}/server.key" "${cert_dir}/priv.key"
            install -m 0644 "${cert_tmp}/ca.pem" "${cert_dir}/ca.pem"
        else
            install -m 0644 "${root}/tests/certs/cert.pem" "${cert_dir}/cert.pem"
            if [[ -f "${ca_pem_source}" ]]; then
                install -m 0644 "${ca_pem_source}" "${cert_dir}/ca.pem"
            else
                install -m 0644 "${root}/tests/certs/cert.pem" "${cert_dir}/ca.pem"
            fi
            install -m 0644 "${root}/tests/certs/key.pem" "${cert_dir}/key.pem"
            install -m 0644 "${root}/tests/certs/key.pem" "${cert_dir}/priv.key"
        fi
        if [[ -d "${cert_tmp}" ]]; then
            find "${cert_tmp}" -mindepth 1 -delete 2>/dev/null || true
            rmdir "${cert_tmp}" 2>/dev/null || true
        fi
    else
        install -m 0644 "${root}/tests/certs/cert.pem" "${cert_dir}/cert.pem"
        if [[ -f "${ca_pem_source}" ]]; then
            install -m 0644 "${ca_pem_source}" "${cert_dir}/ca.pem"
        else
            install -m 0644 "${root}/tests/certs/cert.pem" "${cert_dir}/ca.pem"
        fi
        install -m 0644 "${root}/tests/certs/key.pem" "${cert_dir}/key.pem"
        install -m 0644 "${root}/tests/certs/key.pem" "${cert_dir}/priv.key"
    fi

    if [[ ! -s "${www_dir}/index.html" ]]; then
        printf '<!doctype html><html><body>zig-quic interop fixture</body></html>\n' > "${www_dir}/index.html"
    fi
    if [[ ! -s "${www_dir}/5000" ]]; then
        dd if=/dev/urandom of="${www_dir}/5000" bs=5000 count=1 status=none
    fi
    if [[ ! -s "${www_dir}/10000" ]]; then
        dd if=/dev/urandom of="${www_dir}/10000" bs=10000 count=1 status=none
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    prepare_local_interop_assets "$@"
fi
