FROM martenseemann/quic-network-simulator-endpoint:latest

# Install Zig compiler
RUN apt-get update && apt-get install -y wget xz-utils && \
    wget -q https://ziglang.org/download/0.15.1/zig-linux-x86_64-0.15.1.tar.xz && \
    tar -xf zig-linux-x86_64-0.15.1.tar.xz && \
    mv zig-linux-x86_64-0.15.1 /opt/zig && \
    rm zig-linux-x86_64-0.15.1.tar.xz && \
    ln -s /opt/zig/zig /usr/local/bin/zig && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /quic

# Copy source code
COPY . /quic/

# Build the QNS endpoint binary
RUN zig build -Drelease-safe=true qns-endpoint && \
    cp zig-out/bin/qns-endpoint /usr/local/bin/qns-endpoint && \
    chmod +x /usr/local/bin/qns-endpoint

# Create version file
RUN echo "zig-quic-$(date +%Y%m%d)-$(git rev-parse --short HEAD 2>/dev/null || echo dev)" > /quic/version.txt

# Copy run script
COPY interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT ["/run_endpoint.sh"]
