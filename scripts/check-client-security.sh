#!/bin/sh
# Scan every interop client and fail the job if any scan or prerequisite fails.
# Each scan has its own working directory so one failure cannot redirect later scans.
set -u

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd) || exit 1
status=0

scan() {
    label=$1
    shift
    echo "Scanning $label"
    if "$@"; then
        echo "PASS: $label"
    else
        echo "FAIL: $label" >&2
        status=1
    fi
}

rust_scan() (
    # Memory-unsoundness advisories are warnings by default; treat them as failures.
    cd "$root/$1" && cargo audit --deny unsound
)

go_scan() (
    cd "$root/$1" && go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
)

go_binary_scan() (
    cd "$root/test-clients/quic-test-legacy" &&
        go build -o "$temporary/$1" "./$1" &&
        go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 -mode=binary "$temporary/$1"
)

case ${1-} in
    rust)
        for dir in clients/rust test-clients/legacy-clients/rust test-clients/quinn-client; do
            scan "$dir" rust_scan "$dir"
        done
        ;;
    go)
        temporary=$(mktemp -d) || exit 1
        trap 'rm -rf -- "$temporary"' EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM
        for dir in examples/interop test-clients/quic-test-legacy/xnet-quic test-clients/quic-go-client test-clients/legacy-clients/go; do
            scan "$dir" go_scan "$dir"
        done
        # This legacy module contains independent programs with duplicate main
        # functions. Build and scan each binary instead of treating it as a package.
        for src in client.go server.go test_client.go test_client_comprehensive.go; do
            scan "test-clients/quic-test-legacy/$src" go_binary_scan "$src"
        done
        ;;
    *)
        echo "Usage: $0 go|rust" >&2
        exit 2
        ;;
esac
exit "$status"
