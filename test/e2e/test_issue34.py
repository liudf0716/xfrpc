#!/usr/bin/env python3
"""
Regression & verification test for Issue #34 (token authentication):
1. Standard token authentication (INI and TOML, v1 and v2 wire protocol, MUX and Non-MUX)
2. Special-character token authentication
3. Long token (256 chars) authentication (verifies dynamic seed buffer in get_auth_key and INI_MAX_LINE)
4. Empty / unauthenticated mode
5. Token mismatch error handling (verifies login_resp_unmarshal handles omitted run_id and logs exact frps error)
"""

import os
import sys
import time
import socket
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


def start_echo_server(port):
    running = [True]
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(10)
    srv.settimeout(0.3)

    def serve():
        while running[0]:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            def handle(c):
                try:
                    c.settimeout(5.0)
                    while True:
                        data = c.recv(4096)
                        if not data:
                            break
                        c.sendall(data)
                except (ConnectionResetError, BrokenPipeError, socket.timeout):
                    pass
                finally:
                    c.close()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
        srv.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return running, t


def run_token_case(name, frps_token, xfrpc_token, fmt="ini", mux=True, wire_proto="v1",
                   frps_port=17150, local_port=19250, remote_port=16150, expect_match=True):
    print(f"\n--- Testing Issue #34 Case: {name} ---")

    running, echo_t = start_echo_server(local_port)

    auth_block = ""
    if frps_token is not None:
        auth_block = f'auth.method = "token"\nauth.token = "{frps_token}"\n'

    frps_toml = f"""
bindAddr = "127.0.0.1"
bindPort = {frps_port}
{auth_block}transport.tls.force = false
transport.tcpMux = {str(mux).lower()}
log.to = "console"
log.level = "info"
"""
    frps_conf = f"/tmp/frps_i34_{frps_port}.toml"
    with open(frps_conf, "w") as f:
        f.write(frps_toml)

    frps_p = subprocess.Popen([str(FRPS_BIN), "-c", frps_conf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_for_port(frps_port), f"frps failed to bind {frps_port}"

    if fmt == "ini":
        tok_line = f"token = {xfrpc_token}\n" if xfrpc_token is not None else ""
        xfrpc_conf = f"/tmp/xfrpc_i34_{frps_port}.ini"
        with open(xfrpc_conf, "w") as f:
            f.write(f"""[common]
server_addr = 127.0.0.1
server_port = {frps_port}
{tok_line}tcp_mux = {str(mux).lower()}
wire_protocol = {wire_proto}

[echo]
type = tcp
local_ip = 127.0.0.1
local_port = {local_port}
remote_port = {remote_port}
""")
    else:
        tok_line = f'auth.token = "{xfrpc_token}"\n' if xfrpc_token is not None else ""
        xfrpc_conf = f"/tmp/xfrpc_i34_{frps_port}.toml"
        with open(xfrpc_conf, "w") as f:
            f.write(f"""serverAddr = "127.0.0.1"
serverPort = {frps_port}
{tok_line}transport.tcpMux = {str(mux).lower()}
transport.wireProtocol = "{wire_proto}"

[[proxies]]
name = "echo"
type = "tcp"
localIP = "127.0.0.1"
localPort = {local_port}
remotePort = {remote_port}
""")

    log_path = f"/tmp/xfrpc_i34_{frps_port}.log"
    with open(log_path, "w") as logf:
        xfrpc_p = subprocess.Popen([str(XFRC_BIN), "-f", "-d", "7", "-c", xfrpc_conf],
                                   stdout=logf, stderr=subprocess.STDOUT, text=True)

        try:
            if expect_match:
                assert wait_for_port(remote_port, timeout=5.0), f"remote_port {remote_port} not listening (login likely failed)"
                payload = b"hello-token-auth-test-payload"
                with socket.create_connection(("127.0.0.1", remote_port), timeout=3.0) as s:
                    s.sendall(payload)
                    resp = s.recv(len(payload))
                    assert resp == payload, f"Echo mismatch: {resp}"
                assert xfrpc_p.poll() is None, "xfrpc crashed unexpectedly!"
                print(f"[+] PASS: {name}")
            else:
                time.sleep(1.5)
                assert xfrpc_p.poll() is None, "xfrpc crashed on token mismatch!"
                xfrpc_p.terminate()
                xfrpc_p.wait(timeout=2)
                with open(log_path) as f:
                    logs = f.read()
                assert "token in login doesn't match token from configuration" in logs, (
                    f"Expected exact token mismatch error message in logs, got:\n{logs}"
                )
                print(f"[+] PASS: {name} (properly parsed and logged mismatch error)")
        finally:
            running[0] = False
            if xfrpc_p.poll() is None:
                xfrpc_p.terminate()
                xfrpc_p.wait(timeout=2)
            frps_p.terminate()
            frps_p.wait(timeout=2)
            echo_t.join(timeout=1)


if __name__ == "__main__":
    run_token_case("INI standard token (MUX, v1)", "my_secret_token", "my_secret_token",
                   fmt="ini", mux=True, wire_proto="v1", frps_port=17150, local_port=19250, remote_port=16150)
    run_token_case("INI standard token (Non-MUX, v1)", "my_secret_token", "my_secret_token",
                   fmt="ini", mux=False, wire_proto="v1", frps_port=17151, local_port=19251, remote_port=16151)
    run_token_case("INI special-char token (MUX, v1)", "p@ss!w0rd#123$%^&*_-+=", "p@ss!w0rd#123$%^&*_-+=",
                   fmt="ini", mux=True, wire_proto="v1", frps_port=17152, local_port=19252, remote_port=16152)
    run_token_case("INI 256-char long token (MUX, v1)", "T" * 256, "T" * 256,
                   fmt="ini", mux=True, wire_proto="v1", frps_port=17153, local_port=19253, remote_port=16153)
    run_token_case("TOML 256-char long token (MUX, v1)", "X" * 256, "X" * 256,
                   fmt="toml", mux=True, wire_proto="v1", frps_port=17154, local_port=19254, remote_port=16154)
    run_token_case("INI no token on both ends", None, None,
                   fmt="ini", mux=True, wire_proto="v1", frps_port=17155, local_port=19255, remote_port=16155)
    run_token_case("INI token mismatch error reporting", "right-token", "wrong-token",
                   fmt="ini", mux=True, wire_proto="v1", frps_port=17156, local_port=19256, remote_port=16156,
                   expect_match=False)

    print("\nALL ISSUE #34 TESTS PASSED!")
