FROM alpine:latest AS builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    git \
    pkgconfig \
    python3 \
    libc-dev \
    file-dev \
    libzip-dev \
    openssl-dev \
    linux-headers \
    meson \
    ninja

WORKDIR /build
# Install radare2 (for build only)
RUN git clone --depth 1 https://github.com/radareorg/radare2.git && \
    cd radare2 && \
    ./sys/install.sh && \
    cd .. 

RUN git clone --depth 1 https://github.com/radareorg/radare2-mcp.git && \
    cd radare2-mcp && \
    make && \
    cp r2mcp /usr/local/bin/

# Create /data volume for binary analysis
WORKDIR /data
VOLUME ["/data"]

# Environment setup for r2mcp
ENV R2MCP_DEBUG=0

# Simply set the entrypoint
ENTRYPOINT ["/usr/local/bin/r2mcp"]

# Instructions for users:
# IMPORTANT: Always run with `-i` flag to keep stdin open:
#   docker run -i --rm r2mcp