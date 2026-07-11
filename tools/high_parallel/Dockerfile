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

# Drop to an unprivileged user before running the test binary. /tmp is
# world-writable (sticky bit) so ZIG_*_CACHE_DIR and HOME both remain usable
# for a non-root user; /workspace is chowned in case sources are baked in
# rather than bind-mounted at runtime.
RUN groupadd -r zig && useradd -r -g zig -d /nonexistent -s /usr/sbin/nologin zig \
    && chown -R zig:zig /workspace
USER zig

CMD ["bash", "-lc", "zig version && zig build test -Dtest-filter=high_parallel_scale"]
