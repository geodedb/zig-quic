FROM debian:bookworm-slim

ARG ZIG_VERSION=0.16.0
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl git libssl-dev xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) zig_arch="x86_64-linux" ;; \
        arm64) zig_arch="aarch64-linux" ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${zig_arch}-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz; \
    mkdir -p /opt/zig; \
    tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; \
    ln -s /opt/zig/zig /usr/local/bin/zig; \
    rm -f /tmp/zig.tar.xz

WORKDIR /workspace

ENV HOME=/tmp \
    ZIG_LOCAL_CACHE_DIR=/tmp/zig-local-cache \
    ZIG_GLOBAL_CACHE_DIR=/tmp/zig-global-cache

CMD ["bash", "-lc", "zig version && zig build test -Dtest-filter=high_parallel_scale"]
