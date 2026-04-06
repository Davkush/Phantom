# Phase 9: Network Orchestration & Reproducible Environment
# Stage 1: Build
FROM rust:1.75-slim-bookworm as builder

# Install build dependencies for Plonky2 (clang, cmake) and OpenSSL
RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    clang \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/phantom
COPY . .

# Build the release binary for the node
RUN cargo build --release -p phantom-node

# Stage 2: Injected Runtime
FROM debian:bookworm-slim

# Install network tools (iproute2 for tc, procps for ps, ifconfig via net-tools)
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    iproute2 \
    procps \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /usr/src/phantom/target/release/phantom-node /usr/local/bin/
# Copy the entrypoint script
COPY phantom-node/entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

# Metrics (9091), SOCKS5 (9050), QUIC (443)
EXPOSE 9091 9050 443/udp

ENTRYPOINT ["entrypoint.sh"]
