# Use the latest Alpine as base image
FROM alpine:latest

# Set environment variables
ENV FRP_VERSION=0.61.0
ENV XFRPC_VERSION=4.04.856

# Install required packages
RUN apk add --no-cache \
    libevent \
    libevent-dev \
    openssl \
    openssl-dev \
    libc-dev \
    gcc \
    make \
    git \
    curl \
    tar \
    gzip \
    cmake \
    linux-headers \
    json-c-dev \
    musl-dev \
    zlib-dev \
    pcre-dev

# Create necessary directories
RUN mkdir -p /usr/local/frp /usr/local/xfrpc

# Download and install frp
RUN cd /tmp && \
    curl -L https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_amd64.tar.gz | tar xz && \
    mv frp_${FRP_VERSION}_linux_amd64/frps /usr/local/frp/ && \
    rm -rf frp_${FRP_VERSION}_linux_amd64

# Clone and build xfrpc
RUN cd /tmp && \
    git clone https://github.com/liudf0716/xfrpc.git && \
    cd xfrpc && \
    mkdir build && \
    cd build && \
    cmake -D THIRDPARTY_STATIC_BUILD=ON .. && \
    make && \
    mv xfrpc /usr/local/xfrpc/ && \
    rm -rf /tmp/xfrpc

# Create default frps configuration in TOML format
RUN echo 'bindPort = 7000' > /usr/local/frp/frps.toml && \
    echo 'dashboardPort = 7500' >> /usr/local/frp/frps.toml && \
    echo 'dashboardUser = "admin"' >> /usr/local/frp/frps.toml && \
    echo 'dashboardPwd = "admin"' >> /usr/local/frp/frps.toml && \
    echo 'auth.token = "12345678"' >> /usr/local/frp/frps.toml

# Create default xfrpc configuration
RUN echo "[common]" > /usr/local/xfrpc/xfrpc.ini && \
    echo "server_addr = 127.0.0.1" >> /usr/local/xfrpc/xfrpc.ini && \
    echo "server_port = 7000" >> /usr/local/xfrpc/xfrpc.ini && \
    echo "token = 12345678" >> /usr/local/xfrpc/xfrpc.ini

# Create startup script
RUN echo '#!/bin/sh' > /usr/local/bin/start.sh && \
    echo 'cd /usr/local/frp && ./frps -c frps.toml &' >> /usr/local/bin/start.sh && \
    echo 'sleep 2' >> /usr/local/bin/start.sh && \
    echo 'cd /usr/local/xfrpc && ./xfrpc -c xfrpc.ini' >> /usr/local/bin/start.sh && \
    chmod +x /usr/local/bin/start.sh

# Expose necessary ports
EXPOSE 7000 7500

# Set working directory
WORKDIR /usr/local/xfrpc

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/start.sh"]