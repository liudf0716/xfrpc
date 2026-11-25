![xfrpc](https://user-images.githubusercontent.com/1182593/213063003-73501d3b-1a22-4f4a-8f3f-4ca3268b5bee.png)

[English](README.md) | [中文文档](README_zh.md)

## What is xfrpc?

**xfrpc** is a lightweight, high-performance reverse proxy client for [frp](https://github.com/fatedier/frp), written in pure C for **OpenWrt routers, embedded Linux, and IoT devices** with constrained flash and RAM.

While official Go `frpc` binaries typically require 15+ MB of storage, `xfrpc` compiles to **~197 KB (`.apk`) / ~418 KB installed** on `aarch64` OpenWrt while maintaining compatibility with **`frps` up to v0.72.0** (`wireProtocol` v1 & v2, TOML & INI configs).

---

## Feature Compatibility (vs Official `frpc v0.72.0`)

### Supported Core & Mainstream Features

| Category | Feature | xfrpc | Official frpc (v0.72.0) |
| :--- | :--- | :---: | :---: |
| **Proxy Types** | `tcp`, `udp`, `http`, `https` | Yes | Yes |
| | `tcpmux` (`httpconnect`, `routeByHTTPUser`) | Yes | Yes |
| | `stcp` (Secret TCP + visitor) | Yes | Yes |
| | `sudp` (Secret UDP + visitor) | Yes | Yes |
| | `xtcp` (P2P NAT hole punching + `fallbackTo`) | Yes | Yes |
| **Transports** | `tcp`, `tls` (System CAs + `trustedCaFile`, mTLS, `disableCustomTLSFirstByte`) | Yes | Yes |
| | `quic` (via `ngtcp2`, `-DENABLE_QUIC=ON`) | Yes | Yes |
| | `websocket` (`ws`), `wss` (WebSocket over TLS) | Yes | Yes |
| | `transport.wireProtocol = v1` / `v2` (JSON + AES-256-GCM AEAD) | Yes | Yes |
| | `transport.tcpMux`, `poolCount`, `dialServerTimeout`, `dialServerKeepalive`, `connectServerLocalIP` | Yes | Yes |
| **Auth & Security** | `auth.method = "token"` / `"oidc"` | Yes | Yes |
| | `auth.additionalScopes` (`HeartBeats`, `NewWorkConns`) | Yes | Yes |
| | `useEncryption` (AES-128-CFB) & `useCompression` (Snappy) | Yes | Yes |
| **Traffic & HA** | `bandwidthLimit` (`client` token bucket / `server`) | Yes | Yes |
| | `proxyProtocolVersion` (`v1` / `v2`) | Yes | Yes |
| | `loadBalancer` (`group`, `groupKey`) & `healthCheck` (`tcp`, `http`) | Yes | Yes |
| | `metadatas`, `annotations`, `requestHeaders.set`, `responseHeaders.set` | Yes | Yes |
| **Client Plugins** | `socks5` (with RFC 1929 username/password auth) | Yes | Yes |
| | `http_proxy` (Basic auth + `CONNECT` & HTTP forwarding) | Yes | Yes |
| | `static_file` (`localPath`, `stripPrefix`, Basic auth) | Yes | Yes |
| | `unix_domain_socket` | Yes | Yes |
| | `https2http`, `https2https`, `http2https`, `tls2raw` | Yes | Yes |
| | `http2http` | Partial (TCP forward only, no `Host` rewrite) | Yes |
| **Config & CLI** | TOML (`frpc.toml`) & legacy INI | Yes | Yes |
| | `includes` (glob), `start` filter, `enabled`, `loginFailExit`, `natHoleSTUNServer` | Yes | Yes |
| | `SIGHUP` hot-reload, `xfrpc verify -c <file>`, `xfrpc version` | Yes | Yes |

### Unsupported Features (vs Official `frpc v0.72.0`)

To keep the binary minimal for embedded devices, the following official `frpc` features are **not supported**:

* **`kcp` transport protocol**
* **`VirtualNet` (`virtualNet` / `virtual_net` TUN device)**
* **`transport.proxyURL` dialing** (parsed with a warning log; connecting to `frps` via an upstream HTTP/SOCKS5 proxy is not implemented)
* **`webServer` (Client Admin UI / HTTP API) & `metricsServer` (`/metrics`, `/healthz`)**
* **YAML / JSON config formats**, **Go `text/template` expressions** (`{{ .Envs.* }}`), and **`ValueSource`**
* **HTTP/2 (`enableHTTP2`)** in `https2http` / `https2https` plugins & `hostHeaderRewrite` in `http2http`
* **CLI subcommands** `reload`, `status`, `stop`, `nathole discover`, and config-less CLI proxy flags

### Extra Features Unique to `xfrpc`

Beyond official `frpc`, `xfrpc` provides features tailored for routers and IoT deployments:

* **Built-in Utility Plugins**:
  * `telnetd`: embedded lightweight Telnet daemon
  * `httpd`: embedded HTTP server
  * `instaloader` & `youtubedl`: media download plugins
* **Time-Window Access Control**: `startTime` / `endTime` (`start_time` / `end_time` in INI) to restrict the active hours (0–23) of any proxy.
* **XDPI Protocol Inspection**: `serviceType` / `service_type` (`mstsc`, `rdp`, `vnc`, `ssh`, `telnet`, `http`, `https`) for pre-connect protocol verification.
* **Legacy `type = "socks5"` Proxy Type**: supported alongside standard `[proxies.plugin]` (`type = "socks5"`).
* **OpenWrt Native Ecosystem**: official OpenWrt `apk` package, UCI configuration (`/etc/config/xfrpc`), and `luci-app-xfrpc` Web UI.

---

## Architecture

![Architecture](https://user-images.githubusercontent.com/1182593/196329678-1781b4e9-2355-4863-be3f-e128b31cc82c.png)

---

## How to Build

### Install Dependencies (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libjson-c-dev libevent-dev libssl-dev zlib1g-dev
```

### Standard Build

```bash
git clone https://github.com/liudf0716/xfrpc.git
cd xfrpc
cmake -B build
cmake --build build -j
```

**CMake Build Options:**

| Option | Default | Description |
| :--- | :--- | :--- |
| `-DUSE_WOLFSSL=ON` | `ON` | Use wolfSSL as TLS backend (automatically falls back to OpenSSL if not found) |
| `-DENABLE_QUIC=ON` | `OFF` | Enable QUIC transport via `ngtcp2` |
| `-DBUILD_STATIC=ON` | `OFF` | Build a fully static binary (`-static` with `.a` libraries) |
| `-DDEBUG=ON` | `OFF` | Enable debug logging and AddressSanitizer (`-fsanitize=address -fsanitize=leak`) |

### Build Static Binary (Linux / Alpine / Cross-Compile)

```bash
# Native static build on Ubuntu/Debian
cmake -B build-static -DDEBUG=OFF -DENABLE_SANITIZER=OFF -DBUILD_STATIC=ON
cmake --build build-static -j

# Alpine static build via Docker
DOCKER_BUILDKIT=1 docker build --output out -f docker/Dockerfile.static .

# Cross-compile static binary via Docker (MIPS, MIPSEL, ARM, ARM64)
DOCKER_BUILDKIT=1 docker build --build-arg TARGET_TRIPLE=mips-linux-musl --output out -f docker/Dockerfile.cross .
DOCKER_BUILDKIT=1 docker build --build-arg TARGET_TRIPLE=mipsel-linux-musl --output out -f docker/Dockerfile.cross .
DOCKER_BUILDKIT=1 docker build --build-arg TARGET_TRIPLE=arm-linux-musleabihf --output out -f docker/Dockerfile.cross .
DOCKER_BUILDKIT=1 docker build --build-arg TARGET_TRIPLE=aarch64-linux-musl --output out -f docker/Dockerfile.cross .
```

### Build on OpenWrt

`xfrpc` is included in the official OpenWrt packages feed:
* In `make menuconfig`: `Network` → `Web Servers/Proxies` → `xfrpc`
* Or install directly on OpenWrt (24.10+):
  ```bash
  apk update && apk add xfrpc luci-app-xfrpc
  ```

---

## Quick Start

Download `frps` from [fatedier/frp releases](https://github.com/fatedier/frp/releases) and run it on your public server:

```toml
# frps.toml
bindPort = 7000
auth.token = "your_secret_token"
```

```bash
./frps -c frps.toml
```

### 1. Basic TCP & Wire Protocol v2 (TOML)

```toml
# xfrpc.toml
serverAddr = "your_server_ip"
serverPort = 7000
auth.method = "token"
auth.token = "your_secret_token"
transport.wireProtocol = "v2"

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6000
```

Verify and run:

```bash
xfrpc verify -c xfrpc.toml
xfrpc -c xfrpc.toml -f
```

### 2. WebSocket Secure (`wss`) Transport

`wss` automatically enables TLS without the legacy `0x17` custom first byte, making it compatible with Nginx/Caddy/Cloudflare TLS termination:

```toml
serverAddr = "frp.example.com"
serverPort = 443
auth.token = "your_secret_token"
transport.protocol = "wss"
transport.wireProtocol = "v2"
transport.tls.serverName = "frp.example.com"

[[proxies]]
name = "router_ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6022
```

### 3. SUDP (Secret UDP) & STCP (Private Access)

**Provider (`xfrpc_provider.toml`):**

```toml
serverAddr = "your_server_ip"
serverPort = 7000
auth.token = "your_secret_token"

[[proxies]]
name = "secret_dns"
type = "sudp"
localIP = "127.0.0.1"
localPort = 53
secretKey = "shared_secret_key"
```

**Visitor (`xfrpc_visitor.toml`):**

```toml
serverAddr = "your_server_ip"
serverPort = 7000
auth.token = "your_secret_token"

[[visitors]]
name = "dns_visitor"
type = "sudp"
serverName = "secret_dns"
secretKey = "shared_secret_key"
bindAddr = "127.0.0.1"
bindPort = 5353
```

### 4. Client Plugins (`socks5`, `http_proxy`, `static_file`, `tls2raw`)

```toml
[[proxies]]
name = "my_socks5"
type = "tcp"
remotePort = 1080
[proxies.plugin]
type = "socks5"
username = "user"
password = "password"

[[proxies]]
name = "my_http_proxy"
type = "tcp"
remotePort = 8080
[proxies.plugin]
type = "http_proxy"
httpUser = "user"
httpPassword = "password"

[[proxies]]
name = "my_static"
type = "tcp"
remotePort = 8000
[proxies.plugin]
type = "static_file"
localPath = "/www"
stripPrefix = "/static"
```

### 5. CLI Options & Hot-Reload

```bash
xfrpc verify -c xfrpc.toml      # Validate configuration syntax
xfrpc version                   # Show version
xfrpc -c xfrpc.toml -f -d 7     # Run in foreground with debug logs
xfrpc -c xfrpc.toml -d 0        # Run in daemon/release mode
kill -HUP $(pidof xfrpc)        # Hot-reload configuration
```

---

## OpenWrt LuCI Web UI

If you are running `xfrpc` on OpenWrt, [luci-app-xfrpc](https://github.com/openwrt/luci/tree/master/applications/luci-app-xfrpc) is included in the official OpenWrt LuCI repository and provides a full web interface for configuring `xfrpc` via UCI (`/etc/config/xfrpc`).

---

## How to Contribute

See [CONTRIBUTING.md](https://github.com/liudf0716/xfrpc/blob/master/CONTRIBUTING.md) for details on submitting patches and the contribution workflow.

## Contact

QQ Group: [331230369](https://jq.qq.com/?_wv=1027&k=47QGEhL)

## Star History

[![Star History Chart](https://star-history.dera.page/svg?repos=liudf0716/xfrpc&type=Date)](https://star-history.dera.page/#liudf0716/xfrpc&Date)

## Donation

Alipay:

![Alipay](https://user-images.githubusercontent.com/1182593/169465135-d4522479-4068-4714-ab58-987d7d7eb338.png)

WeChat Pay:

![WeChat](https://user-images.githubusercontent.com/1182593/169465249-db1b495e-078e-4cab-91fc-96dab3320b06.png)
