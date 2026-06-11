
![xfrpc](https://user-images.githubusercontent.com/1182593/213063003-73501d3b-1a22-4f4a-8f3f-4ca3268b5bee.png)


## What is xfrpc 

The xfrpc project is an implementation of frp client written in C language for OpenWRT and IOT system. The main motivation of this project is to provide a lightweight solution for devices with limited resources such as OpenWRT devices which often have limited ROM and RAM space. The project aims to provide a frp client that uses less space and memory than other available options.

## Development Status

xfrpc partially compitable with latest frp release feature, It targets to fully compatible with latest frp release.

the following table is detail  compatible feature:

| Feature  | xfrpc | frpc |
| ------------- | ------------- | ---------|
| tcp  | Yes |	 Yes  |
| tcpmux  | Yes |	 Yes  |
| http  | Yes |	 Yes  |
| https  | Yes |  Yes  |
| custom_domains | Yes | Yes |
| subdomain | Yes | Yes |
| socks5 | Yes | No |
| use_encryption | No | Yes |
| use_compression | No | Yes |
| udp  | Yes |  Yes  |
| p2p  | No |  Yes  |
| xtcp  | Yes |  Yes  |
| stcp  | Yes |  Yes  |
| quic transport  | Yes |  Yes  |



## Architecture


![Architecture](https://user-images.githubusercontent.com/1182593/196329678-1781b4e9-2355-4863-be3f-e128b31cc82c.png)


## How to build

### Build on Ubuntu 20.04.3 LTS

xfrpc requires libevent, json-c, and a TLS library (wolfSSL or OpenSSL).

**Install dependencies on Ubuntu/Debian:**

```
sudo apt-get update
sudo apt-get install -y libjson-c-dev libevent-dev libssl-dev
```

**Install dependencies on OpenWrt:**

wolfSSL is the default TLS library on OpenWrt and is recommended. No additional TLS package is needed for basic functionality.

**Build:**

```
git clone https://github.com/liudf0716/xfrpc.git
cd xfrpc
mkdir build && cd build
cmake ..
make
```

**Build options:**

| Option | Default | Description |
|---|---|---|
| `-DUSE_WOLFSSL=ON` | ON | Use wolfSSL as TLS backend (falls back to OpenSSL if not found) |
| `-DENABLE_QUIC=ON` | OFF | Enable QUIC transport via ngtcp2 (requires ngtcp2 + nghttp3) |
| `-DDEBUG=ON` | OFF | Enable debug build with address sanitizer |

**Build with QUIC support:**

```
cmake .. -DENABLE_QUIC=ON
make
```

**Build with OpenSSL instead of wolfSSL:**

```
cmake .. -DUSE_WOLFSSL=OFF
make
```
This will compile xfrpc and create an executable in the build directory. You can then run xfrpc using the executable by running the appropriate command in terminal.

### TLS Backend

xfrpc uses **wolfSSL** as the default TLS backend, which is the standard TLS library on OpenWrt. wolfSSL is smaller, faster, and has native QUIC support compared to OpenSSL.

On systems where wolfSSL is not installed, xfrpc automatically falls back to OpenSSL. You can explicitly choose the backend:

```
# Use wolfSSL (default, recommended)
cmake .. -DUSE_WOLFSSL=ON

# Use OpenSSL
cmake .. -DUSE_WOLFSSL=OFF
```

### Build static binary in Alpine container

Under project root directory

```shell
$ DOCKER_BUILDKIT=1 docker build --output out . -f docker/Dockerfile

$ ls out/
xfrpc
```

### Build on OpenWrt master

xfrpc is included in the OpenWrt community since version 1.04.515, which allows users to easily include it in their custom firmware images. It is recommended to use the latest version of xfrpc as it may have bug fixes and new features.

To include xfrpc in your OpenWrt firmware image, you can use the make menuconfig command to open the configuration menu. In the menu, navigate to "Network" and select "Web Servers/Proxies" and then select xfrpc. This will include xfrpc in the firmware image that will be built.

### Build xfrpc with asan(For detect memory leak)

When encountering a segment fault, please use the following command to compile xfrpc:

```shell
cmake -DCMAKE_BUILD_TYPE=Debug ..
```

Now your xfrpc can detect memory leak.We will add it in ci flow in future.

## Quick start for use

**before using xfrpc, you should get frps server: [frps](https://github.com/fatedier/frp/releases)**

frps is a server-side component of the FRP (Fast Reverse Proxy) system and it is used to forward incoming connections to xfrpc. 

+ frps 

To run frps, you can use the following command, providing it with the path to the frps configuration file:

```
./frps -c frps.ini
```

A sample frps.ini configuration file is provided in the example, which binds frps to listen on port 7000.

```
# frps.ini
[common]
bind_port = 7000
```

+ xfrpc tcp support

xfrpc is a client-side component of the FRP system and it can be used to forward TCP connections. To forward incoming TCP connections to a local service, you can configure xfrpc with the following example in xfrpc_mini.ini file

```
#xfrpc_mini.ini 
[common]
server_addr = your_server_ip
server_port = 7000

[ssh]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = 6128
```

+ xfrpc quic transport support

xfrpc can connect to frps using QUIC (UDP-based transport) instead of TCP. QUIC provides faster connection establishment (0-RTT), built-in encryption (TLS 1.3), and better performance on lossy networks.

**frps configuration:**

```
# frps.ini
[common]
bind_port = 7000
quicBindPort = 7000
```

**xfrpc configuration:**

```
# xfrpc_quic.ini
[common]
server_addr = your_server_ip
server_port = 7000
protocol = quic
quic_bind_port = 7000

[ssh]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = 6128
```

**Configuration options:**

| Option | Default | Description |
|---|---|---|
| `protocol` | `tcp` | Transport protocol: `tcp` or `quic` |
| `quic_bind_port` | 0 | frps QUIC listening port (required when protocol=quic) |

> **Note:** QUIC support requires building with `-DENABLE_QUIC=ON` and the ngtcp2/nghttp3 libraries installed.

This configuration tells the frp server (frps) to forward incoming connections on remote port 6128 to the xfrpc client. The xfrpc client, in turn, will forward these connections to the local service running on IP address 127.0.0.1 and port 22.

+ xfrpc tcpmux support

TCPMux proxy uses HTTP CONNECT multiplexing on frps's `tcpmuxHTTPConnectPort` to route connections by domain. Multiple tcpmux proxies share a single connection pool, making it more resource-efficient than individual tcp proxies.

First, enable tcpmux on frps:

```
# frps.ini
[common]
bind_port = 7000
tcpmuxHTTPConnectPort = 5000
```

Then configure xfrpc with tcpmux proxies:

```
# xfrpc_tcpmux.ini
[common]
server_addr = your_server_ip
server_port = 7000
tcp_mux = 1

[web]
type = tcpmux
local_ip = 127.0.0.1
local_port = 80
custom_domains = web.example.com
multiplexer = httpconnect

[api]
type = tcpmux
local_ip = 127.0.0.1
local_port = 8080
subdomain = api
multiplexer = httpconnect
```

Access `web.example.com:5000` or `api.your_server_domain:5000` to reach the local services through the TCPMux multiplexer.

+ xfrpc stcp support

STCP (Secret TCP) proxy allows you to expose services privately without opening a public port on frps. Unlike tcp/udp proxies, STCP requires a preshared key (`sk`) for authentication — only visitors with the correct key can access the service. This is ideal for sensitive services like SSH, databases, or internal APIs that you don't want exposed to the public internet.

**How it works:**

STCP involves two xfrpc instances:
1. **Service provider** (Machine B): Registers an STCP proxy with frps, specifying the local service to expose and a secret key.
2. **Visitor** (Machine C): Connects to frps as a visitor, using the same secret key, and binds a local port that tunnels through to the remote service.

The traffic flow is: `Machine C (visitor) → frps → Machine B (provider) → local service`

**Step 1: frps server configuration**

No special configuration needed for frps beyond the basic setup:

```
# frps.ini
[common]
bind_port = 7000
```

**Step 2: Service provider (Machine B) — expose a local service via STCP**

```
# xfrpc_stcp_server.ini
[common]
server_addr = your_server_ip
server_port = 7000

[secret_ssh]
type = stcp
local_ip = 127.0.0.1
local_port = 22
sk = my_secret_key_abc123
# Allowed visitor users (default: same user only)
# Use '*' to allow all users, or comma-separated list like 'user1, user2'
allow_users = *
```

Key fields:
- `type = stcp` — Use the STCP proxy type
- `sk` — Preshared secret key (must match on both sides)
- `allow_users` — Who can connect as a visitor (`*` = any user, or comma-separated usernames)

**Step 3: Visitor (Machine C) — access the remote service**

```
# xfrpc_stcp_visitor.ini
[common]
server_addr = your_server_ip
server_port = 7000

[visitor:stcp_ssh_visitor]
type = stcp
server_name = secret_ssh
sk = my_secret_key_abc123
bind_addr = 127.0.0.1
bind_port = 6000
```

Key fields:
- `[visitor:name]` — Section prefix `visitor:` indicates this is a visitor configuration
- `server_name` — Must match the proxy name on the provider side (`secret_ssh`)
- `sk` — Must match the secret key on the provider side
- `bind_addr` / `bind_port` — Local address and port to listen on for incoming connections

**Step 4: Connect to the service**

On Machine C, connect to the SSH service on Machine B through the visitor tunnel:

```
ssh -oPort=6000 127.0.0.1
```

> **Note:** When using `user` in the common section, both the provider and visitor xfrpc instances should use the same `user` value to ensure they are recognized as belonging to the same user group.

+ xfrpc http&https support

 Supporting HTTP and HTTPS in xfrpc requires additional configuration compared to supporting just TCP. In the frps.ini configuration file, the vhost_http_port and vhost_https_port options must be added to specify the ports that the frp server (frps) will listen on for incoming HTTP and HTTPS connections.
 
```
# frps.ini
[common]
bind_port = 7000
vhost_http_port = 80
vhost_https_port = 443
```

It is important to ensure that the xfrpc client is properly configured to communicate with the frp server by specifying the correct server address and port in the xfrpc configuration file.

```
# xfrpc_mini.ini 
[common]
server_addr = x.x.x.x
server_port = 7000

[http]
type = http
local_port = 80
local_ip = 127.0.0.1
custom_domains = www.example.com

[https]
type = https
local_port = 443
local_ip = 127.0.0.1
custom_domains = www.example.com
```

The FRP server (frps) will forward incoming HTTP and HTTPS connections to the domain "www.example.com" to the location where xfrpc is running on the local IP and port specified in the configuration file (127.0.0.1:80 and 127.0.0.1:443 respectively).

It is important to note that the domain name "www.example.com" should be pointed to the public IP address of the FRP server (frps) so that when a user's HTTP and HTTPS connections visit the domain, the FRP server can forward those connections to the xfrpc client. This can be done by configuring a DNS server or by using a dynamic DNS service.

+ Run in debug mode 

In order to troubleshooting problem when run xfrpc, you can use debug mode. which has more information when running.

```shell
xfrpc -c frpc_mini.ini -f -d 7 
```

+ Run in release mode :

```shell
xfrpc -c frpc_mini.ini -d 0
```

It is important to note that running xfrpc in release mode will generate less log output and will run faster than in debug mode, so it is the recommended way to run xfrpc in production environment.

## Openwrt luci configure ui

If you're running xfrpc on an OpenWRT device, luci-app-xfrpc is a good option to use as it provides a web-based interface for configuring and managing xfrpc. luci-app-xfrpc is a module for the LuCI web interface, which is the default web interface for OpenWRT.

luci-app-xfrpc was adopted by the LuCI project, which is the official web interface for OpenWRT. This means that it is a supported and well-maintained option for managing xfrpc on OpenWRT devices.

luci-app-xfrpc can be installed via the opkg package manager on OpenWRT and provides a user-friendly interface for configuring the xfrpc client, including options for setting up multiple connections, custom domains and more.

## How to contribute our project

See [CONTRIBUTING](https://github.com/liudf0716/xfrpc/blob/master/CONTRIBUTING.md) for details on submitting patches and the contribution workflow.

## Contact

QQ群 ： [331230369](https://jq.qq.com/?_wv=1027&k=47QGEhL)


## Please support us and star our project

[![Star History Chart](https://api.star-history.com/svg?repos=liudf0716/xfrpc&type=Date)](https://star-history.com/#liudf0716/xfrpc&Date)

## 打赏

支付宝打赏

![支付宝打赏](https://user-images.githubusercontent.com/1182593/169465135-d4522479-4068-4714-ab58-987d7d7eb338.png)


微信打赏


![微信打赏](https://user-images.githubusercontent.com/1182593/169465249-db1b495e-078e-4cab-91fc-96dab3320b06.png)


 <!--
 
## 广告

想学习OpenWrt开发，但是摸不着门道？自学没毅力？基础太差？怕太难学不会？跟着佐大学OpenWrt开发入门培训班助你能学有所成

报名地址：https://forgotfun.org/2018/04/openwrt-training-2018.html

-->
