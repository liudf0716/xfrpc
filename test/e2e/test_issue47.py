#!/usr/bin/env python3
"""
Regression test for Issue #47:
1. Non-mux mode: remote connection close must close the local connection (no orphaned connections).
2. MUX mode: when remote sends data and FIN, local server must receive all data without truncation and receive EOF.
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
CONFIGS_DIR = SCRIPT_DIR / "configs"
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

def test_non_mux_connection_cleanup():
    print("\n--- Testing Issue #47 Case 1: Non-MUX connection cleanup ---")
    active_local_conns = 0
    lock = threading.Lock()
    server_running = True
    local_port = 19101

    def local_server():
        nonlocal active_local_conns
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", local_port))
        srv.listen(10)
        srv.settimeout(0.5)

        while server_running:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            with lock:
                active_local_conns += 1
            def handle_client(c):
                nonlocal active_local_conns
                try:
                    while True:
                        data = c.recv(4096)
                        if not data:
                            break
                        c.sendall(data)
                except Exception:
                    pass
                finally:
                    c.close()
                    with lock:
                        active_local_conns -= 1
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()
        srv.close()

    srv_thread = threading.Thread(target=local_server, daemon=True)
    srv_thread.start()

    # Generate custom configs
    tmp_dir = Path("/tmp/issue47_test")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    frps_cfg = tmp_dir / "frps_nomux.toml"
    xfrpc_cfg = tmp_dir / "xfrpc_nomux.ini"

    frps_port = 17100
    remote_port = 16101

    frps_cfg.write_text(f"""
bindAddr = "127.0.0.1"
bindPort = {frps_port}
auth.method = "token"
auth.token = "testtoken123"
transport.tcpMux = false
transport.tls.force = false
transport.heartbeatTimeout = 90
""")

    xfrpc_cfg.write_text(f"""
[common]
server_addr = 127.0.0.1
server_port = {frps_port}
token = testtoken123
tcp_mux = 0

[tcp_test]
type = tcp
local_ip = 127.0.0.1
local_port = {local_port}
remote_port = {remote_port}
""")

    frps_log = tmp_dir / "frps_mux.log"
    xfrpc_log = tmp_dir / "xfrpc_mux.log"
    frps_f = open(frps_log, "w", buffering=1)
    xfrpc_f = open(xfrpc_log, "w", buffering=1)
    frps_p = subprocess.Popen([str(FRPS_BIN), "-c", str(frps_cfg)], stdout=frps_f, stderr=frps_f)
    time.sleep(0.5)
    assert wait_for_port(frps_port), "frps failed to start"

    xfrpc_p = subprocess.Popen([str(XFRC_BIN), "-c", str(xfrpc_cfg), "-f"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.5)
    if not wait_for_port(remote_port):
        print("xfrpc log:")
        with open(xfrpc_log) as f:
            print(f.read())
        print("frps log:")
        with open(frps_log) as f:
            print(f.read())
        assert False, "xfrpc proxy port not ready"

    try:
        # Establish multiple sequential visitor connections and close them
        for i in range(5):
            s = socket.create_connection(("127.0.0.1", remote_port), timeout=2.0)
            s.sendall(b"hello world\n")
            resp = s.recv(1024)
            assert resp == b"hello world\n", f"Echo mismatch: {resp}"
            # Close visitor connection
            s.close()
            time.sleep(0.2)

        # Wait a moment and check active local connections
        time.sleep(0.5)
        with lock:
            print(f"Active local connections remaining: {active_local_conns}")
            assert active_local_conns == 0, f"Expected 0 active local connections, but found {active_local_conns} leaked!"

        print("SUCCESS: Case 1 PASSED (0 local connections leaked in non-MUX mode)")
    finally:
        server_running = False
        xfrpc_p.terminate()
        try:
            out, err = xfrpc_p.communicate(timeout=2)
            print("--- xfrpc stderr ---")
            print(err)
        except Exception:
            pass
        frps_p.terminate()
        frps_p.wait()

def test_mux_eof_and_data_integrity():
    print("\n--- Testing Issue #47 Case 2: MUX mode trailing data & EOF (half-close) ---")
    local_port = 19102
    server_running = True
    received_bytes = []
    received_eof = False

    def local_server():
        nonlocal received_eof
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", local_port))
        srv.listen(10)
        srv.settimeout(0.5)

        while server_running:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            def handle_client(c):
                nonlocal received_eof
                buf = bytearray()
                while True:
                    data = c.recv(4096)
                    if not data:
                        # Got EOF!
                        received_eof = True
                        break
                    buf.extend(data)
                received_bytes.append(bytes(buf))
                # Echo back the entire buffer
                c.sendall(bytes(buf))
                c.close()
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()
        srv.close()

    srv_thread = threading.Thread(target=local_server, daemon=True)
    srv_thread.start()

    tmp_dir = Path("/tmp/issue47_test")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    frps_cfg = tmp_dir / "frps_mux.toml"
    xfrpc_cfg = tmp_dir / "xfrpc_mux.ini"

    frps_port = 17101
    remote_port = 16102

    frps_cfg.write_text(f"""
bindAddr = "127.0.0.1"
bindPort = {frps_port}
auth.method = "token"
auth.token = "testtoken123"
transport.tcpMux = true
transport.tls.force = false
transport.heartbeatTimeout = 90
""")

    xfrpc_cfg.write_text(f"""
[common]
server_addr = 127.0.0.1
server_port = {frps_port}
token = testtoken123
tcp_mux = 1
log_level = 7

[tcp_mux_test]
type = tcp
local_ip = 127.0.0.1
local_port = {local_port}
remote_port = {remote_port}
""")

    frps_log = tmp_dir / "frps_mux.log"
    xfrpc_log = tmp_dir / "xfrpc_mux.log"
    frps_f = open(frps_log, "w", buffering=1)
    xfrpc_f = open(xfrpc_log, "w", buffering=1)
    frps_p = subprocess.Popen([str(FRPS_BIN), "-c", str(frps_cfg)], stdout=frps_f, stderr=frps_f)
    time.sleep(0.5)
    assert wait_for_port(frps_port), "frps failed to start"

    xfrpc_p = subprocess.Popen([str(XFRC_BIN), "-c", str(xfrpc_cfg), "-f"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.5)
    if not wait_for_port(remote_port):
        print("xfrpc log:")
        with open(xfrpc_log) as f:
            print(f.read())
        print("frps log:")
        with open(frps_log) as f:
            print(f.read())
        assert False, "xfrpc proxy port not ready"

    try:
        # Clear any probe connections from wait_for_port
        time.sleep(0.5)
        received_bytes.clear()
        received_eof = False

        # Connect to proxy port, send large payload, and close connection (remote disconnects)
        test_payload = b"X" * 32768 + b"END_OF_TRANSMISSION"
        s = socket.create_connection(("127.0.0.1", remote_port), timeout=5.0)
        s.sendall(test_payload)
        s.close()

        # Wait for local server to receive all data and EOF
        time.sleep(1.0)
        assert received_eof, "Local server did NOT receive EOF when remote disconnected!"
        assert len(received_bytes) > 0, "Local server received nothing!"
        assert received_bytes[0] == test_payload, f"Payload mismatch! Received {len(received_bytes[0])} bytes, expected {len(test_payload)}"

        print(f"SUCCESS: Case 2 PASSED (Remote sent {len(test_payload)} bytes and closed; local received full payload and EOF cleanly)")
    finally:
        server_running = False
        xfrpc_p.terminate()
        try:
            out, err = xfrpc_p.communicate(timeout=2)
            print("--- xfrpc stderr ---")
            print(err)
        except Exception:
            pass
        frps_p.terminate()
        frps_p.wait()

if __name__ == "__main__":
    try:
        test_non_mux_connection_cleanup()
        test_mux_eof_and_data_integrity()
        print("\n===============================")
        print("ALL ISSUE #47 TESTS PASSED!")
        print("===============================\n")
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
