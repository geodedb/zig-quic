#!/bin/sh
# Exercise the real scanner, including cases that must still be detected.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
config=${GITLEAKS_TEST_CONFIG:-$root/.gitleaks.toml}
scanner=${GITLEAKS_BIN:-gitleaks}
command -v "$scanner" >/dev/null
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM

# Public OpenSSL release signer identifiers; these are not credentials.
current='B146647E45A7B33947AB226B2A2C87D161692D40'
previous='BA5473A2B0587B07FB27CF2D216094DFD0CB81EF'
# A deterministic synthetic value, never a real credential.
unknown=$(printf '%s' 'SONNY-4789 synthetic negative control' | sha256sum | cut -c 1-40)

scan() {
    label=$1
    expected=$2
    relative_path=$3
    value=$4
    case_dir="$fixture/$label"
    mkdir -p "$case_dir/$(dirname -- "$relative_path")"
    printf 'OPENSSL_RELEASE_KEY_CURRENT="%s"\n' "$value" >"$case_dir/$relative_path"
    actual=0
    (cd "$case_dir" && "$scanner" dir --config "$config" --exit-code 17 \
        --redact --no-banner --log-level error .) >"$fixture/$label.log" 2>&1 || actual=$?
    if [ "$actual" -ne "$expected" ]; then
        printf 'FAIL: %s: scanner exit %s, expected %s\n' "$label" "$actual" "$expected" >&2
        cat "$fixture/$label.log" >&2
        exit 1
    fi
    printf 'PASS: %s\n' "$label"
}

scan current-public-signer 0 scripts/install-openssl-fips.sh "$current"
scan previous-public-signer 0 scripts/install-openssl-fips.sh "$previous"
scan other-installer-value 17 scripts/install-openssl-fips.sh "$unknown"
scan current-outside-installer 17 control.env "$current"
scan previous-outside-installer 17 control.env "$previous"
scan nested-installer-path 17 nested/scripts/install-openssl-fips.sh "$current"
scan installer-path-suffix 17 scripts/install-openssl-fips.sh.backup "$current"
scan public-value-prefix 17 scripts/install-openssl-fips.sh "a$current"
scan public-value-suffix 17 scripts/install-openssl-fips.sh "${current}a"
