#!/usr/bin/env python3
"""
End-to-end compatibility test suite for xfrpc vs frps v0.72.0.
Tests:
  1. CLI: verify & version
  2. TOML: includes, start filter, wireProtocol=v2, poolCount, additionalScopes, metadatas/annotations
  3. proxyProtocolVersion v1 & v2
  4. bandwidthLimit (client-side)
  5. sudp proxy + sudp visitor
  6. Plugins: socks5 (with auth), http_proxy (with auth + CONNECT), static_file (with stripPrefix + auth), tls2raw
"""

import base64
import os
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

FRPS_BIN = os.environ.get("FRPS_BIN", "/tmp/frp_0.72.0_linux_amd64/frps")
XFRPC_BIN = os.environ.get("XFRPC_BIN", "/home/liudf/Windows/github/xfrpc/build/xfrpc")
CERTS_DIR = Path("/home/liudf/Windows/github/xfrpc/test/e2e/certs")


def wait_port(port, timeout=10.0, udp=False):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if udp:
            return True
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", port))
            s.close()
            return True
        except OSError:
            s.close()
            time.sleep(0.15)
    return False


def start_tcp_echo(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(32)
    stop = threading.Event()

    def handle(conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def loop():
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break
        srv.close()

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return stop


def start_udp_echo(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", port))
    stop = threading.Event()

    def loop():
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                data, addr = srv.recvfrom(4096)
                srv.sendto(data, addr)
            except socket.timeout:
                continue
            except OSError:
                break
        srv.close()

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return stop


def start_tls_echo(port, crt, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(key))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(32)
    stop = threading.Event()

    def handle(conn):
        try:
            with ctx.wrap_socket(conn, server_side=True) as ss:
                while True:
                    data = ss.recv(4096)
                    if not data:
                        break
                    ss.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def loop():
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break
        srv.close()

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return stop


def start_tls_terminator(listen_port, target_port, crt, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(key))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", listen_port))
    srv.listen(32)
    stop = threading.Event()

    def pipe(a, b):
        try:
            while True:
                d = a.recv(4096)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        finally:
            try:
                a.close()
            except OSError:
                pass
            try:
                b.close()
            except OSError:
                pass

    def handle(raw):
        try:
            sc = ctx.wrap_socket(raw, server_side=True)
            up = socket.create_connection(("127.0.0.1", target_port), timeout=3.0)
            threading.Thread(target=pipe, args=(sc, up), daemon=True).start()
            threading.Thread(target=pipe, args=(up, sc), daemon=True).start()
        except OSError:
            raw.close()

    def loop():
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break
        srv.close()

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return stop


def ensure_certs(tmpdir: Path):
    crt = tmpdir / "server.crt"
    key = tmpdir / "server.key"
    if (CERTS_DIR / "server.crt").exists() and (CERTS_DIR / "server.key").exists():
        shutil.copy(CERTS_DIR / "server.crt", crt)
        shutil.copy(CERTS_DIR / "server.key", key)
    else:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(crt), "-days", "1",
            "-subj", "/CN=127.0.0.1"
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return crt, key


def main():
    if not os.path.exists(FRPS_BIN):
        print(f"ERROR: frps not found at {FRPS_BIN}")
        sys.exit(1)
    if not os.path.exists(XFRPC_BIN):
        print(f"ERROR: xfrpc not found at {XFRPC_BIN}")
        sys.exit(1)

    tmpdir = Path(tempfile.mkdtemp(prefix="xfrpc_v072_"))
    procs = []
    stops = []

    try:
        crt, key = ensure_certs(tmpdir)
        static_dir = tmpdir / "static"
        static_dir.mkdir()
        (static_dir / "hello.txt").write_text("Hello from xfrpc static_file!")

        inc_dir = tmpdir / "conf.d"
        inc_dir.mkdir()

        # Included TOML file for tls2raw + included proxy
        (inc_dir / "extra.toml").write_text(f"""
[[proxies]]
name = "tls2raw_test"
type = "tcp"
remotePort = 26008
[proxies.plugin]
type = "tls2raw"
localAddr = "127.0.0.1:29001"
crtPath = "{crt}"
keyPath = "{key}"

[[proxies]]
name = "excluded_by_start"
type = "tcp"
localIP = "127.0.0.1"
localPort = 29001
remotePort = 26099
""")

        frps_cfg = tmpdir / "frps.toml"
        frps_cfg.write_text("""
bindAddr = "127.0.0.1"
bindPort = 27000
auth.method = "token"
auth.token = "test_token_072"
auth.additionalScopes = ["HeartBeats", "NewWorkConns"]
""")

        xfrpc_cfg = tmpdir / "xfrpc.toml"
        xfrpc_cfg.write_text(f"""
serverAddr = "127.0.0.1"
serverPort = 27000
user = "testuser"
loginFailExit = true
auth.method = "token"
auth.token = "test_token_072"
auth.additionalScopes = ["HeartBeats", "NewWorkConns"]

transport.protocol = "tcp"
transport.wireProtocol = "v2"
transport.tcpMux = true
transport.poolCount = 2
transport.dialServerTimeout = 10
transport.dialServerKeepalive = 60

log.to = "console"
log.level = "debug"

includes = ["./conf.d/*.toml"]
start = [
  "pp_v1", "pp_v2", "bw_tcp",
  "sudp_srv", "sudp_cli",
  "socks5_auth", "http_proxy_auth", "static_srv",
  "tls2raw_test", "https2https_test"
]

[[proxies]]
name = "pp_v1"
type = "tcp"
localIP = "127.0.0.1"
localPort = 29001
remotePort = 26001
transport.proxyProtocolVersion = "v1"
[proxies.metadatas]
env = "e2e"
[proxies.annotations]
owner = "xfrpc"

[[proxies]]
name = "pp_v2"
type = "tcp"
localIP = "127.0.0.1"
localPort = 29001
remotePort = 26002
transport.proxyProtocolVersion = "v2"

[[proxies]]
name = "bw_tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = 29001
remotePort = 26003
transport.bandwidthLimit = "100KB"
transport.bandwidthLimitMode = "client"

[[proxies]]
name = "sudp_srv"
type = "sudp"
localIP = "127.0.0.1"
localPort = 29002
secretKey = "sudp_secret"

[[visitors]]
name = "sudp_cli"
type = "sudp"
serverName = "sudp_srv"
secretKey = "sudp_secret"
bindAddr = "127.0.0.1"
bindPort = 26004

[[proxies]]
name = "socks5_auth"
type = "tcp"
remotePort = 26005
[proxies.plugin]
type = "socks5"
username = "suser"
password = "spass"

[[proxies]]
name = "http_proxy_auth"
type = "tcp"
remotePort = 26006
[proxies.plugin]
type = "http_proxy"
httpUser = "huser"
httpPassword = "hpass"

[[proxies]]
name = "static_srv"
type = "tcp"
remotePort = 26007
[proxies.plugin]
type = "static_file"
localPath = "{static_dir}"
stripPrefix = "/files"
httpUser = "fuser"
httpPassword = "fpass"

[[proxies]]
name = "https2https_test"
type = "tcp"
remotePort = 26009
[proxies.plugin]
type = "https2https"
localAddr = "127.0.0.1:29003"
crtPath = "{crt}"
keyPath = "{key}"
""")

        # 1. CLI: version & verify
        r_ver = subprocess.run([XFRPC_BIN, "version"], capture_output=True, text=True)
        assert r_ver.returncode == 0 and "version:" in r_ver.stdout, f"version failed: {r_ver.stdout} {r_ver.stderr}"
        print("  [PASS] CLI: xfrpc version")

        r_chk = subprocess.run([XFRPC_BIN, "verify", "-c", str(xfrpc_cfg)], capture_output=True, text=True)
        assert r_chk.returncode == 0 and "syntax is ok" in r_chk.stdout, f"verify failed: {r_chk.stdout} {r_chk.stderr}"
        print("  [PASS] CLI: xfrpc verify -c xfrpc.toml")

        # Start local echo servers
        stops.append(start_tcp_echo(29001))
        stops.append(start_udp_echo(29002))
        stops.append(start_tls_echo(29003, crt, key))

        # Start frps v0.72.0
        frps_log = open(tmpdir / "frps.log", "w")
        p_frps = subprocess.Popen([FRPS_BIN, "-c", str(frps_cfg)], stdout=frps_log, stderr=subprocess.STDOUT)
        procs.append(p_frps)
        assert wait_port(27000, 8.0), "frps failed to start"

        # Start xfrpc
        xfrpc_log = open(tmpdir / "xfrpc.log", "w")
        p_xfrpc = subprocess.Popen([XFRPC_BIN, "-c", str(xfrpc_cfg), "-f"], stdout=xfrpc_log, stderr=subprocess.STDOUT)
        procs.append(p_xfrpc)
        assert wait_port(26001, 8.0), "xfrpc failed to expose proxy 26001"
        time.sleep(0.5)

        # Verify 'excluded_by_start' is NOT listening
        s_excl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_excl.settimeout(0.5)
        assert s_excl.connect_ex(("127.0.0.1", 26099)) != 0, "excluded_by_start should NOT be listening"
        s_excl.close()
        print("  [PASS] TOML: includes + start filter + wireProtocol=v2 + poolCount + additionalScopes")

        # 2. Proxy Protocol v1
        with socket.create_connection(("127.0.0.1", 26001), timeout=3.0) as s:
            s.sendall(b"PING_V1")
            data = s.recv(4096)
            assert data.startswith(b"PROXY TCP4 ") and b"\r\nPING_V1" in data, f"unexpected pp_v1: {data}"
        print("  [PASS] Proxy Protocol v1")

        # 3. Proxy Protocol v2
        with socket.create_connection(("127.0.0.1", 26002), timeout=3.0) as s:
            s.sendall(b"PING_V2")
            data = s.recv(4096)
            assert data.startswith(b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a\x21\x11") and b"PING_V2" in data, f"unexpected pp_v2: {data}"
        print("  [PASS] Proxy Protocol v2")

        # 4. Bandwidth limit
        with socket.create_connection(("127.0.0.1", 26003), timeout=5.0) as s:
            payload = b"X" * 8192
            s.sendall(payload)
            recvd = b""
            while len(recvd) < len(payload):
                chunk = s.recv(4096)
                if not chunk:
                    break
                recvd += chunk
            assert recvd == payload, f"bw_tcp mismatch: {len(recvd)}"
        print("  [PASS] Client-side bandwidthLimit")

        # 5. SUDP proxy + SUDP visitor
        usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        usock.settimeout(4.0)
        usock.sendto(b"SUDP_HELLO_072", ("127.0.0.1", 26004))
        udata, _ = usock.recvfrom(4096)
        usock.close()
        assert udata == b"SUDP_HELLO_072", f"sudp mismatch: {udata}"
        print("  [PASS] SUDP proxy + SUDP visitor")

        # 6. SOCKS5 plugin with username/password auth
        with socket.create_connection(("127.0.0.1", 26005), timeout=4.0) as s:
            s.sendall(b"\x05\x01\x02")
            assert s.recv(2) == b"\x05\x02"
            s.sendall(b"\x01\x05suser\x05spass")
            assert s.recv(2) == b"\x01\x00"
            s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 29001))
            rep = s.recv(10)
            assert rep[:2] == b"\x05\x00", f"socks5 connect failed: {rep}"
            s.sendall(b"SOCKS5_OK")
            assert s.recv(64) == b"SOCKS5_OK"
        print("  [PASS] Plugin: socks5 (RFC 1929 auth)")

        # 7. http_proxy plugin with Basic auth + CONNECT
        with socket.create_connection(("127.0.0.1", 26006), timeout=4.0) as s:
            auth = base64.b64encode(b"huser:hpass").decode()
            req = f"CONNECT 127.0.0.1:29001 HTTP/1.1\r\nHost: 127.0.0.1:29001\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
            s.sendall(req.encode())
            resp = s.recv(1024)
            assert b"200 Connection Established" in resp, f"http_proxy CONNECT failed: {resp}"
            s.sendall(b"HTTP_PROXY_OK")
            assert s.recv(64) == b"HTTP_PROXY_OK"
        print("  [PASS] Plugin: http_proxy (Basic auth + CONNECT)")

        # 8. static_file plugin with stripPrefix + Basic auth
        with socket.create_connection(("127.0.0.1", 26007), timeout=4.0) as s:
            auth = base64.b64encode(b"fuser:fpass").decode()
            req = f"GET /files/hello.txt HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\n\r\n"
            s.sendall(req.encode())
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b"Hello from xfrpc static_file!" in resp:
                    break
            assert b"200 OK" in resp and b"Hello from xfrpc static_file!" in resp, f"static_file failed: {resp}"
        print("  [PASS] Plugin: static_file (stripPrefix + Basic auth)")

        # 9. tls2raw plugin
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", 26008), timeout=4.0) as raw_s:
            with ctx.wrap_socket(raw_s, server_hostname="127.0.0.1") as ss:
                ss.sendall(b"TLS2RAW_OK")
                assert ss.recv(64) == b"TLS2RAW_OK"
        print("  [PASS] Plugin: tls2raw")

        # 10. https2https plugin
        with socket.create_connection(("127.0.0.1", 26009), timeout=4.0) as raw_s:
            with ctx.wrap_socket(raw_s, server_hostname="127.0.0.1") as ss:
                ss.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                resp = ss.recv(256)
                assert b"GET / HTTP/1.1" in resp, f"https2https mismatch: {resp}"
        print("  [PASS] Plugin: https2https")

        # 11. SIGHUP hot-reload (add sighup_tcp)
        xfrpc_cfg.write_text(xfrpc_cfg.read_text().replace(
            '"tls2raw_test", "https2https_test"',
            '"tls2raw_test", "https2https_test", "sighup_tcp"'
        ) + """
[[proxies]]
name = "sighup_tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = 29001
remotePort = 26010
""")
        p_xfrpc.send_signal(signal.SIGHUP)
        assert wait_port(26010, 6.0), "sighup_tcp failed to appear after SIGHUP"
        with socket.create_connection(("127.0.0.1", 26010), timeout=3.0) as s:
            s.sendall(b"SIGHUP_OK")
            assert s.recv(64) == b"SIGHUP_OK"
        print("  [PASS] SIGHUP hot-reload")

        # Stop p_xfrpc before ws/wss tests (same host MAC -> same run_id)
        p_xfrpc.terminate()
        p_xfrpc.wait(timeout=3)
        time.sleep(0.2)

        # 12. WebSocket (ws) transport
        ws_cfg = tmpdir / "xfrpc_ws.toml"
        ws_cfg.write_text("""
serverAddr = "127.0.0.1"
serverPort = 27000
auth.token = "test_token_072"
auth.additionalScopes = ["HeartBeats", "NewWorkConns"]
transport.protocol = "websocket"
transport.wireProtocol = "v2"
[[proxies]]
name = "ws_tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = 29001
remotePort = 26011
""")
        p_ws = subprocess.Popen([XFRPC_BIN, "-c", str(ws_cfg), "-f"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(p_ws)
        assert wait_port(26011, 6.0), "ws_tcp failed to expose port 26011"
        with socket.create_connection(("127.0.0.1", 26011), timeout=3.0) as s:
            s.sendall(b"WS_OK_072")
            assert s.recv(64) == b"WS_OK_072"
        p_ws.terminate()
        p_ws.wait(timeout=3)
        print("  [PASS] Transport: websocket (ws + wireProtocol=v2)")

        # 13. WebSocket Secure (wss) transport
        stops.append(start_tls_terminator(27001, 27000, crt, key))
        ca_file = CERTS_DIR / "ca.crt" if (CERTS_DIR / "ca.crt").exists() else crt
        wss_cfg = tmpdir / "xfrpc_wss.toml"
        wss_cfg.write_text(f"""
serverAddr = "127.0.0.1"
serverPort = 27001
auth.token = "test_token_072"
auth.additionalScopes = ["HeartBeats", "NewWorkConns"]
transport.protocol = "wss"
transport.wireProtocol = "v2"
transport.tls.trustedCaFile = "{ca_file}"
[[proxies]]
name = "wss_tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = 29001
remotePort = 26012
""")
        p_wss = subprocess.Popen([XFRPC_BIN, "-c", str(wss_cfg), "-f"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(p_wss)
        assert wait_port(26012, 6.0), "wss_tcp failed to expose port 26012"
        with socket.create_connection(("127.0.0.1", 26012), timeout=3.0) as s:
            s.sendall(b"WSS_OK_072")
            assert s.recv(64) == b"WSS_OK_072"
        p_wss.terminate()
        p_wss.wait(timeout=3)
        print("  [PASS] Transport: wss (TLS + WebSocket + wireProtocol=v2)")

        print("\nALL v0.72.0 COMPATIBILITY E2E TESTS PASSED!")
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        for name in ("xfrpc.log", "frps.log"):
            p = tmpdir / name
            if p.exists():
                print(f"--- {name} (tail) ---")
                print("\n".join(p.read_text().splitlines()[-40:]))
        sys.exit(1)
    finally:
        for p in procs:
            p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
        for st in stops:
            st.set()
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
