# Build stage
FROM alpine:latest AS builder

# Set environment variables
ENV FRP_VERSION=0.61.0
ENV XFRPC_VERSION=4.04.856

# Install build dependencies
RUN apk add --no-cache \
    libevent-dev \
    openssl-dev \
    libc-dev \
    gcc \
    make \
    git \
    curl \
    tar \
    gzip \
    cmake \
    json-c-dev \
    zlib-dev \
    linux-headers

# Create build directory
WORKDIR /build

# Download and build frp
RUN curl -L https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_amd64.tar.gz | tar xz && \
    mv frp_${FRP_VERSION}_linux_amd64/frps /build/

# Clone and build xfrpc
RUN git clone https://github.com/liudf0716/xfrpc.git && \
    cd xfrpc && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make && \
    cp xfrpc /build/xfrpc_binary && \
    cd /build && \
    rm -rf xfrpc

# Runtime stage
FROM alpine:latest

# Define environment variables for xfrpc configuration
ENV SERVER_ADDR=127.0.0.1
ENV SERVER_PORT=7000
ENV TOKEN=12345678
ENV CCL_ADDRESS=127.0.0.1
ENV CCL_LOCAL_PORT=12322
ENV CCL_REMOTE_PORT=12322
ENV DRL_LOCAL_PORT=12321
ENV DRL_REMOTE_PORT=12321

# Create non-root user
RUN adduser -D -H -h /usr/local/xfrpc xfrpc

# Install runtime dependencies
RUN apk add --no-cache \
    libevent \
    openssl \
    libc-utils \
    json-c \
    zlib

# Create necessary directories
RUN mkdir -p /usr/local/frp /usr/local/xfrpc && \
    chown -R xfrpc:xfrpc /usr/local/frp /usr/local/xfrpc

# Copy binaries from builder
COPY --from=builder /build/frps /usr/local/frp/
COPY --from=builder /build/xfrpc_binary /usr/local/xfrpc/xfrpc

# Set permissions
RUN chmod +x /usr/local/frp/frps /usr/local/xfrpc/xfrpc && \
    chown xfrpc:xfrpc /usr/local/frp/frps /usr/local/xfrpc/xfrpc

# Create default frps configuration in TOML format
RUN echo 'bindPort = 7000' > /usr/local/frp/frps.toml && \
    echo 'dashboardPort = 7500' >> /usr/local/frp/frps.toml && \
    echo 'dashboardUser = "admin"' >> /usr/local/frp/frps.toml && \
    echo 'dashboardPwd = "admin"' >> /usr/local/frp/frps.toml && \
    echo 'auth.token = ${TOKEN}' >> /usr/local/frp/frps.toml && \
    chown xfrpc:xfrpc /usr/local/frp/frps.toml

# Create startup script with dynamic configuration
RUN echo '#!/bin/sh' > /usr/local/bin/start.sh && \
    echo 'cat > /usr/local/xfrpc/xfrpc.ini << EOF' >> /usr/local/bin/start.sh && \
    echo '[common]' >> /usr/local/bin/start.sh && \
    echo "server_addr = ${SERVER_ADDR}" >> /usr/local/bin/start.sh && \
    echo "server_port = ${SERVER_PORT}" >> /usr/local/bin/start.sh && \
    echo "token = ${TOKEN}" >> /usr/local/bin/start.sh && \
    echo '[drl]' >> /usr/local/bin/start.sh && \
    echo 'type = iod' >> /usr/local/bin/start.sh && \
    echo "local_port = ${DRL_LOCAL_PORT}" >> /usr/local/bin/start.sh && \
    echo "remote_port = ${DRL_REMOTE_PORT}" >> /usr/local/bin/start.sh && \
    echo '[ccl]' >> /usr/local/bin/start.sh && \
    echo 'type = tcp' >> /usr/local/bin/start.sh && \
    echo "local_ip = ${CCL_ADDRESS}" >> /usr/local/bin/start.sh && \
    echo "local_port = ${CCL_LOCAL_PORT}" >> /usr/local/bin/start.sh && \
    echo "remote_port = ${CCL_REMOTE_PORT}" >> /usr/local/bin/start.sh && \
    echo 'EOF' >> /usr/local/bin/start.sh && \
    echo 'cd /usr/local/frp && ./frps -c frps.toml &' >> /usr/local/bin/start.sh && \
    echo 'sleep 2' >> /usr/local/bin/start.sh && \
    echo 'cd /usr/local/xfrpc && ./xfrpc -c xfrpc.ini' >> /usr/local/bin/start.sh && \
    chmod +x /usr/local/bin/start.sh && \
    chown xfrpc:xfrpc /usr/local/bin/start.sh

# Expose necessary ports
EXPOSE  7500 ${DRL_REMOTE_PORT} ${CCL_REMOTE_PORT}

# Set working directory
WORKDIR /usr/local/xfrpc

# Switch to non-root user
USER xfrpc

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/start.sh"]