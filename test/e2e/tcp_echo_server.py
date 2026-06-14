#!/usr/bin/env python3
"""
Simple TCP echo server for xfrpc e2e testing.
Listens on a port and echoes back everything received.
Also supports a 'ping' command that replies 'pong' for quick connectivity checks.
"""

import socket
import sys
import threading
import signal
import os


def handle_client(conn, addr):
    """Handle a single client connection."""
    try:
        with conn:
            conn.settimeout(10)
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                # Special command: ping -> pong
                if data.strip() == b"ping":
                    conn.sendall(b"pong\n")
                else:
                    conn.sendall(data)
    except (ConnectionResetError, BrokenPipeError, socket.timeout):
        pass
    except Exception as e:
        print(f"[echo-server] Error handling {addr}: {e}", file=sys.stderr)


def run_echo_server(port):
    """Run the TCP echo server on the given port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(32)
    print(f"[echo-server] Listening on 127.0.0.1:{port}")

    # Write PID file for easy cleanup
    pid_file = f"/tmp/xfrpc-echo-server-{port}.pid"
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))

    def cleanup(signum, frame):
        print(f"[echo-server] Shutting down (signal {signum})")
        sock.close()
        try:
            os.unlink(pid_file)
        except OSError:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    finally:
        sock.close()
        try:
            os.unlink(pid_file)
        except OSError:
            pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 19001
    run_echo_server(port)
