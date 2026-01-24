# Expect a prebuilt qns-endpoint copied from host to make builds deterministic and offline-friendly.
# Build locally before invoking docker:
#   zig build -Doptimize=ReleaseSafe cli

ARG QNS_IMAGE=martenseemann/quic-network-simulator-endpoint
ARG QNS_TAG=latest

FROM ${QNS_IMAGE}:${QNS_TAG}

WORKDIR /quic

# Copy prebuilt binary from host
COPY zig-out/bin/qns-endpoint /usr/local/bin/qns-endpoint

# Copy run script
COPY interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh /usr/local/bin/qns-endpoint

# Version metadata
ARG VCS_REF="dev"
ARG BUILD_DATE
RUN printf "zig-quic-%s-%s\n" "${BUILD_DATE:-$(date -u +%Y%m%d)}" "${VCS_REF}" > /quic/version.txt

ENTRYPOINT ["/run_endpoint.sh"]

