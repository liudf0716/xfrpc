#!/usr/bin/env python3
"""
Regression test for Issue #37:
Forward TCP port to HTTP proxy or SOCKS5 server with wrong password (auth failure),
verifying that local proxy disconnection (both clean FIN and TCP RST) does not cause
segmentation faults, memory errors (ASan), or unhandled errors in MUX and Non-MUX modes.
"""

import os
import sys
import time
import socket
import struct
import threading
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent.parent
FRPS_BIN = Path(os.environ.get("FRPS_BIN", "/media/windows/github/xfrpc/build/frp_0.71.0_linux_amd64/frps"))
XFRC_BIN = PROJECT_DIR / "build" / "xfrpc"

def wait_for_port(port, host="127.0.0.1", timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.05)
    return False

def run_auth_failure_test(mux=True, send_rst=False):
    mode_str = ("MUX" if mux else "Non-MUX") + (" (RST)" if send_rst else " (FIN)")
    print(f"\n--- Testing Issue #37: Local proxy auth failure [{mode_str}] ---")

    frps_port = 17130 if mux else 17131
    remote_port = 16130 if mux else 16131
    local_port = 19230 if mux else 19231

    server_running = True
    def mock_proxy():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", local_port))
        srv.listen(20)
        srv.settimeout(0.5)

        while server_running:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue

            def handle(c):
                try:
                    c.settimeout(3.0)
                    data = c.recv(1024)
                    if data.startswith(b"\x05"):
                        c.sendall(b"\x05\x02")
                        auth = c.recv(1024)
                        c.sendall(b"\x01\x01")
                        if send_rst:
                            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                        else:
                            time.sleep(0.05)
                        c.close()
                    elif b"HTTP" in data or b"CONNECT" in data:
                        c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nConnection: close\r\n\r\n")
                        if send_rst:
                            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                        else:
                            time.sleep(0.05)
                        c.close()
                    else:
                        c.close()
                except Exception:
                    pass
                finally:
                    try:
                        c.close()
                    except Exception:
                        pass
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
        srv.close()

    th = threading.Thread(target=mock_proxy, daemon=True)
    th.start()

    frps_toml = f"""
bindAddr = "127.0.0.1"
bindPort = {frps_port}
auth.method = "token"
auth.token = "test-token"
transport.tls.force = false
transport.tcpMux = {str(mux).lower()}
log.to = "console"
log.level = "info"
"""
    frps_conf_path = f"/tmp/frps_i37_{mux}_{send_rst}.toml"
    with open(frps_conf_path, "w") as f:
        f.write(frps_toml)

    frps_p = subprocess.Popen([str(FRPS_BIN), "-c", frps_conf_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_for_port(frps_port), "frps failed to bind"

    xfrpc_ini = f"""
[common]
server_addr = 127.0.0.1
server_port = {frps_port}
token = test-token
tcp_mux = {str(mux).lower()}

[socks5-test]
type = tcp
local_ip = 127.0.0.1
local_port = {local_port}
remote_port = {remote_port}
"""
    xfrpc_conf_path = f"/tmp/xfrpc_i37_{mux}_{send_rst}.ini"
    with open(xfrpc_conf_path, "w") as f:
        f.write(xfrpc_ini)

    xfrpc_p = subprocess.Popen([str(XFRC_BIN), "-f", "-d", "7", "-c", xfrpc_conf_path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_for_port(remote_port, timeout=5.0), "remote_port failed to bind"

    try:
        # SOCKS5 auth failure
        for _ in range(5):
            with socket.create_connection(("127.0.0.1", remote_port), timeout=3.0) as s:
                s.sendall(b"\x05\x01\x02")
                resp = s.recv(2)
                assert resp == b"\x05\x02"
                s.sendall(b"\x01\x04user\x05wrong")
                try:
                    resp = s.recv(2)
                    if not send_rst:
                        assert resp == b"\x01\x01"
                except (ConnectionResetError, BrokenPipeError):
                    pass
            time.sleep(0.05)

        # HTTP proxy auth failure
        for _ in range(5):
            with socket.create_connection(("127.0.0.1", remote_port), timeout=3.0) as s:
                s.sendall(b"CONNECT proxy.example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNyOmFiY2Q=\r\n\r\n")
                try:
                    resp = s.recv(1024)
                    if not send_rst:
                        assert b"407" in resp
                except (ConnectionResetError, BrokenPipeError):
                    pass
            time.sleep(0.05)

        assert xfrpc_p.poll() is None, f"xfrpc process crashed in {mode_str}!"
        print(f"[+] {mode_str} passed successfully.")
    finally:
        server_running = False
        xfrpc_p.terminate()
        xfrpc_p.wait()
        frps_p.terminate()
        frps_p.wait()
        th.join(timeout=1)

if __name__ == "__main__":
    run_auth_failure_test(mux=True, send_rst=False)
    run_auth_failure_test(mux=True, send_rst=True)
    run_auth_failure_test(mux=False, send_rst=False)
    run_auth_failure_test(mux=False, send_rst=True)
    print("\nAll Issue #37 test cases passed!")
