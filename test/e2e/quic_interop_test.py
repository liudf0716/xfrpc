#!/usr/bin/env python3
"""
Standalone ngtcp2 ↔ quic-go interop test.

Tests whether a raw QUIC stream opened by xfrpc (ngtcp2) can carry data
to frps (quic-go) without being FIN'd immediately.

This isolates the question: is the work stream FIN a protocol-level
interop issue, or a bug in xfrpc's work stream handling?
"""

import subprocess
import socket
import time
import os
import sys
import signal
import json

FRPS_BIN = "/home/liudf/work/frp/bin/frps"
XFRC_BIN = "/home/liudf/work/xfrpc/build/xfrpc"
FRPS_PORT = 17005
QUIC_PORT = 17006
ECHO_PORT = 19002
TOKEN = "interop-test-token"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def log(msg, color=RESET):
    print(f"{color}{msg}{RESET}", flush=True)


def write_configs():
    """Write test configs."""
    os.makedirs("/tmp/quic-interop", exist_ok=True)

    with open("/tmp/quic-interop/frps.toml", "w") as f:
        f.write(f"""bindAddr = "127.0.0.1"
bindPort = {FRPS_PORT}
quicBindPort = {QUIC_PORT}
auth.method = "token"
auth.token = "{TOKEN}"
transport.tls.force = false
transport.heartbeatTimeout = 90
transport.quic.maxIdleTimeout = 120
transport.quic.keepalivePeriod = 10
transport.quic.maxIncomingStreams = 100000
log.to = "console"
log.level = "debug"
""")

    with open("/tmp/quic-interop/xfrpc.ini", "w") as f:
        f.write(f"""[common]
server_addr = 127.0.0.1
server_port = {FRPS_PORT}
token = {TOKEN}
protocol = quic
quic_bind_port = {QUIC_PORT}

[echo]
type = tcp
local_ip = 127.0.0.1
local_port = {ECHO_PORT}
remote_port = 16005
""")


def start_echo_server():
    """Simple TCP echo server."""
    import threading
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", ECHO_PORT))
    srv.listen(5)

    def handle():
        while True:
            try:
                conn, _ = srv.accept()
                data = conn.recv(65536)
                if data:
                    conn.sendall(data)
                conn.close()
            except:
                break

    t = threading.Thread(target=handle, daemon=True)
    t.start()
    return srv


def wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except:
            time.sleep(0.2)
    return False


def main():
    write_configs()

    log("=== Test 1: Login + proxy registration ===")
    log("Starting frps...")
    frps = subprocess.Popen(
        [FRPS_BIN, "-c", "/tmp/quic-interop/frps.toml"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    time.sleep(2)

    log("Starting echo server...")
    echo_srv = start_echo_server()

    log("Starting xfrpc...")
    xfrpc = subprocess.Popen(
        [XFRC_BIN, "-c", "/tmp/quic-interop/xfrpc.ini", "-f", "-d", "7"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )

    # Wait for proxy to come up
    proxy_port = 16005
    if wait_port(proxy_port, timeout=15):
        log(f"  Proxy port {proxy_port} is open — login + registration OK", GREEN)
    else:
        log(f"  Proxy port {proxy_port} not open — login/registration failed", RED)
        dump_logs(frps, xfrpc)
        cleanup(frps, xfrpc, echo_srv)
        return False

    log("")
    log("=== Test 2: Small data through tunnel (single QUIC packet) ===")
    ok_small = test_echo(proxy_port, b"hello", timeout=5)
    log(f"  Small data: {'PASS' if ok_small else 'FAIL'}", GREEN if ok_small else RED)

    log("")
    log("=== Test 3: Medium data (~1 MTU) ===")
    ok_medium = test_echo(proxy_port, b"A" * 1200, timeout=5)
    log(f"  Medium data: {'PASS' if ok_medium else 'FAIL'}", GREEN if ok_medium else RED)

    log("")
    log("=== Test 4: Large data (multi-packet, >1 QUIC packet) ===")
    ok_large = test_echo(proxy_port, b"B" * 4096, timeout=5)
    log(f"  Large data: {'PASS' if ok_large else 'FAIL'}", GREEN if ok_large else RED)

    log("")
    log("=== Test 5: Multiple sequential connections ===")
    ok_multi = True
    for i in range(3):
        ok = test_echo(proxy_port, f"msg-{i}".encode(), timeout=5)
        if not ok:
            ok_multi = False
            break
    log(f"  Multi-connection: {'PASS' if ok_multi else 'FAIL'}", GREEN if ok_multi else RED)

    # Gather results
    log("")
    log("=" * 50)
    all_pass = ok_small and ok_medium and ok_large and ok_multi
    if all_pass:
        log("ALL TESTS PASSED — ngtcp2↔quic-go interop is WORKING", GREEN)
        log("The issue is in xfrpc's work stream handling, not QUIC protocol", GREEN)
    else:
        log("SOME TESTS FAILED — checking failure pattern...", RED)
        if ok_small and not ok_large:
            log("  Pattern: small OK, large FAIL → data relay/truncation bug", YELLOW)
        elif not ok_small:
            log("  Pattern: all fail → QUIC stream setup or protocol issue", YELLOW)

    dump_logs(frps, xfrpc)
    cleanup(frps, xfrpc, echo_srv)
    return all_pass


def test_echo(port, data, timeout=5):
    """Connect through proxy, send data, check echo."""
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(data)
        received = b""
        deadline = time.time() + timeout
        while len(received) < len(data) and time.time() < deadline:
            chunk = sock.recv(65536)
            if not chunk:
                break
            received += chunk
        sock.close()

        if received == data:
            log(f"    sent {len(data)} bytes, got {len(received)} bytes — MATCH")
            return True
        else:
            log(f"    sent {len(data)} bytes, got {len(received)} bytes — MISMATCH", RED)
            if len(received) > 0:
                log(f"    first 32 sent: {data[:32]!r}")
                log(f"    first 32 recv: {received[:32]!r}")
            return False
    except Exception as e:
        log(f"    connection error: {e}", RED)
        return False


def dump_logs(frps, xfrpc):
    """Dump relevant log lines."""
    log("")
    log("--- FRPS log (last 20 lines) ---", YELLOW)
    try:
        frps.terminate()
        out = frps.stdout.read().decode(errors="replace")
        for line in out.strip().split("\n")[-20:]:
            log(f"  {line}", YELLOW)
    except:
        pass

    log("")
    log("--- XFRC key events ---", YELLOW)
    try:
        xfrpc.terminate()
        out = xfrpc.stdout.read().decode(errors="replace")
        for line in out.strip().split("\n"):
            if any(k in line for k in [
                "stream_close", "FIN", "work stream", "NewWorkConn",
                "start_work", "sp_read_cb", "sp_writev",
                "Proxy service", "recv_stream_data", "Login successful",
                "heartbeat", "error", "Error", "FAIL",
            ]):
                log(f"  {line}", YELLOW)
    except:
        pass


def cleanup(frps, xfrpc, echo_srv):
    for p in [xfrpc, frps]:
        try:
            p.terminate()
            p.wait(timeout=3)
        except:
            try:
                p.kill()
            except:
                pass
    try:
        echo_srv.close()
    except:
        pass


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
