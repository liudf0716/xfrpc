#!/usr/bin/env python3
"""
xfrpc end-to-end test runner.

Tests 4 transport scenarios:
  1. Plain TCP          (tcp_mux=0, no TLS, no QUIC)
  2. TCP + mux          (tcp_mux=1)
  3. QUIC               (protocol=quic)
  4. TLS                (tls_enable=1)

For each scenario the test:
  - starts frps with the scenario config
  - starts xfrpc with the scenario config
  - connects to the remote_port exposed by frps
  - sends test data through the tunnel and verifies the echo reply
  - cleans up all processes

Usage:
  python3 test/e2e/test_proxy.py              # run all scenarios
  python3 test/e2e/test_proxy.py tcp quic     # run specific scenarios
"""

import os
import sys
import time
import socket
import signal
import subprocess
import tempfile
import textwrap
import shutil
from pathlib import Path

# ── paths ────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent.parent          # xfrpc repo root
CONFIGS_DIR = SCRIPT_DIR / "configs"
CERTS_DIR = SCRIPT_DIR / "certs"
ECHO_SERVER_PY = SCRIPT_DIR / "tcp_echo_server.py"
FRPS_BIN = Path("/home/liudf/work/frp/bin/frps")
XFRC_BIN = PROJECT_DIR / "build" / "xfrpc"
ECHO_PORT = 19001

# ── scenario definitions ─────────────────────────────────────────────────
SCENARIOS = {
    "tcp": {
        "desc": "Plain TCP (no mux, no TLS, no QUIC)",
        "frps_cfg": CONFIGS_DIR / "frps-tcp.toml",
        "xfrpc_cfg": CONFIGS_DIR / "xfrpc-tcp.ini",
        "remote_port": 16001,
    },
    "mux": {
        "desc": "TCP + tcp_mux",
        "frps_cfg": CONFIGS_DIR / "frps-mux.toml",
        "xfrpc_cfg": CONFIGS_DIR / "xfrpc-mux.ini",
        "remote_port": 16002,
    },
    "quic": {
        "desc": "QUIC transport (work stream FIN issue — see #QUIC-WS)",
        "frps_cfg": CONFIGS_DIR / "frps-quic.toml",
        "xfrpc_cfg": CONFIGS_DIR / "xfrpc-quic.ini",
        "remote_port": 16003,
    },
    "tls": {
        "desc": "TLS transport",
        "frps_cfg": CONFIGS_DIR / "frps-tls.toml",
        "xfrpc_cfg": CONFIGS_DIR / "xfrpc-tls.ini",
        "remote_port": 16004,
    },
}

# ── colours ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def log(msg, colour=RESET):
    print(f"{colour}{msg}{RESET}", flush=True)


# ── TLS certificate generation ───────────────────────────────────────────
def generate_tls_certs():
    """Generate a self-signed CA + server cert for the TLS test scenario."""
    if CERTS_DIR.exists() and (CERTS_DIR / "ca.crt").exists():
        log("  TLS certs already exist, skipping generation", YELLOW)
        return

    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    ca_key = CERTS_DIR / "ca.key"
    ca_crt = CERTS_DIR / "ca.crt"
    srv_key = CERTS_DIR / "server.key"
    srv_crt = CERTS_DIR / "server.crt"
    srv_csr = CERTS_DIR / "server.csr"

    # CA key + self-signed cert
    _run(["openssl", "genrsa", "-out", str(ca_key), "2048"], check=True)
    _run([
        "openssl", "req", "-x509", "-new", "-nodes",
        "-key", str(ca_key), "-sha256", "-days", "3650",
        "-out", str(ca_crt),
        "-subj", "/C=CN/ST=Test/L=Test/O=xfrpc-e2e/CN=xfrpc-e2e-ca",
    ], check=True)

    # Server key + CSR + signed cert
    _run(["openssl", "genrsa", "-out", str(srv_key), "2048"], check=True)
    _run([
        "openssl", "req", "-new",
        "-key", str(srv_key),
        "-out", str(srv_csr),
        "-subj", "/C=CN/ST=Test/L=Test/O=xfrpc-e2e/CN=127.0.0.1",
    ], check=True)

    # SAN extension so TLS verification passes for 127.0.0.1
    san_ext = CERTS_DIR / "san.cnf"
    san_ext.write_text(textwrap.dedent("""\
        [v3_req]
        subjectAltName = IP:127.0.0.1,DNS:localhost
    """))
    _run([
        "openssl", "x509", "-req",
        "-in", str(srv_csr),
        "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(srv_crt), "-days", "3650", "-sha256",
        "-extfile", str(san_ext), "-extensions", "v3_req",
    ], check=True)

    log("  TLS certs generated OK", GREEN)


# ── process helpers ──────────────────────────────────────────────────────
_PROCS = []          # track for cleanup
_ECHO_PROC = None


def _run(args, **kwargs):
    """Run a command, return CompletedProcess."""
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def start_process(args, label, logfile=None):
    """Start a subprocess, return Popen."""
    log(f"  Starting {label}: {' '.join(str(a) for a in args)}", CYAN)
    lf = open(logfile, "w") if logfile else subprocess.DEVNULL
    p = subprocess.Popen(
        [str(a) for a in args],
        stdout=lf, stderr=subprocess.STDOUT,
        cwd=str(PROJECT_DIR),
    )
    _PROCS.append((p, label, lf))
    return p


def stop_process(p, label, lf=None):
    """Gracefully stop a process."""
    if p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=3)
    if lf and lf is not subprocess.DEVNULL:
        lf.close()


def cleanup_all():
    """Stop every process we started."""
    for p, label, lf in _PROCS:
        stop_process(p, label, lf)
    _PROCS.clear()
    global _ECHO_PROC
    if _ECHO_PROC and _ECHO_PROC.poll() is None:
        _ECHO_PROC.terminate()
        _ECHO_PROC.wait(timeout=3)
        _ECHO_PROC = None


def wait_for_port(port, timeout=10, host="127.0.0.1"):
    """Block until a TCP port is accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)
    return False


def wait_for_file(path, timeout=10):
    """Block until a file exists."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if Path(path).exists():
            return True
        time.sleep(0.2)
    return False


# ── test logic ───────────────────────────────────────────────────────────
def test_echo_through_proxy(remote_port, scenario_name, timeout=10):
    """
    Connect to frps remote_port, send data, verify echo reply.
    Returns (passed: bool, detail: str).
    """
    test_payloads = [
        b"hello xfrpc\n",
        b"A" * 4096 + b"\n",
        b"ping",
        b"\x00\x01\x02\x03binary data\x04\x05\x06\n",
    ]

    try:
        with socket.create_connection(("127.0.0.1", remote_port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            for i, payload in enumerate(test_payloads):
                sock.sendall(payload)
                reply = b""
                # Read until we get at least as many bytes as we sent,
                # or we see the expected pong.
                try:
                    while len(reply) < len(payload):
                        chunk = sock.recv(8192)
                        if not chunk:
                            break
                        reply += chunk
                except socket.timeout:
                    pass

                expected = b"pong\n" if payload.strip() == b"ping" else payload
                if reply != expected:
                    return False, (
                        f"payload #{i} mismatch: sent {len(payload)} bytes, "
                        f"got {len(reply)} bytes. "
                        f"expected starts={expected[:40]!r}, got starts={reply[:40]!r}"
                    )
            return True, f"all {len(test_payloads)} payloads echoed correctly"
    except Exception as e:
        return False, f"connection failed: {e}"


def run_scenario(name):
    """Run a single test scenario. Returns True on success."""
    cfg = SCENARIOS[name]
    log(f"\n{'='*60}", BOLD)
    log(f"  Scenario: {name} — {cfg['desc']}", BOLD)
    log(f"{'='*60}", BOLD)

    frps_log = f"/tmp/xfrpc-e2e-frps-{name}.log"
    xfrpc_log = f"/tmp/xfrpc-e2e-xfrpc-{name}.log"

    # 1. Generate TLS certs if this is the TLS scenario
    if name == "tls":
        generate_tls_certs()

    # 2. Start frps
    frps_p = start_process(
        [FRPS_BIN, "-c", cfg["frps_cfg"]],
        f"frps({name})", frps_log,
    )
    # frps binds to different ports per scenario; wait for the bind port
    # Parse the port from the config
    bind_port = _parse_bind_port(cfg["frps_cfg"])
    if not wait_for_port(bind_port, timeout=8):
        log(f"  FAIL: frps did not bind port {bind_port}", RED)
        _dump_log(frps_log)
        return False
    log(f"  frps ready on port {bind_port}", GREEN)

    # 3. Start echo server (shared across scenarios, only start once)
    global _ECHO_PROC
    if _ECHO_PROC is None or _ECHO_PROC.poll() is not None:
        _ECHO_PROC = start_process(
            [sys.executable, str(ECHO_SERVER_PY), str(ECHO_PORT)],
            "echo-server",
        )
        if not wait_for_port(ECHO_PORT, timeout=5):
            log(f"  FAIL: echo server did not bind port {ECHO_PORT}", RED)
            return False
        log(f"  Echo server ready on port {ECHO_PORT}", GREEN)

    # 4. Start xfrpc
    xfrpc_p = start_process(
        [XFRC_BIN, "-c", cfg["xfrpc_cfg"], "-f"],
        f"xfrpc({name})", xfrpc_log,
    )
    # Wait for xfrpc to register the proxy (remote port becomes reachable)
    remote_port = cfg["remote_port"]
    if not wait_for_port(remote_port, timeout=15):
        log(f"  FAIL: xfrpc proxy did not come up on port {remote_port}", RED)
        _dump_log(xfrpc_log)
        _dump_log(frps_log)
        return False
    log(f"  xfrpc proxy ready on port {remote_port}", GREEN)

    # 5. Test echo through the tunnel
    time.sleep(0.5)  # let the connection settle
    passed, detail = test_echo_through_proxy(remote_port, name)
    if passed:
        log(f"  PASS: {detail}", GREEN)
    else:
        log(f"  FAIL: {detail}", RED)
        _dump_log(xfrpc_log)
        _dump_log(frps_log)

    # 6. Cleanup scenario processes (but keep echo server)
    stop_process(frps_p, f"frps({name})")
    stop_process(xfrpc_p, f"xfrpc({name})")
    _PROCS.clear()

    return passed


def _parse_bind_port(cfg_path):
    """Extract bindPort from a TOML config."""
    text = Path(cfg_path).read_text()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("bindPort"):
            return int(line.split("=")[1].strip().strip('"'))
    return 7000  # fallback


def _dump_log(path):
    """Print the last 30 lines of a log file."""
    p = Path(path)
    if not p.exists():
        return
    lines = p.read_text().splitlines()
    tail = lines[-30:]
    log(f"  --- {path} (last {len(tail)} lines) ---", YELLOW)
    for l in tail:
        log(f"    {l}", YELLOW)


# ── main ─────────────────────────────────────────────────────────────────
def main():
    # Determine which scenarios to run
    if len(sys.argv) > 1:
        requested = sys.argv[1:]
        for r in requested:
            if r not in SCENARIOS:
                log(f"Unknown scenario: {r}. Choose from {list(SCENARIOS.keys())}", RED)
                sys.exit(1)
    else:
        requested = list(SCENARIOS.keys())

    # Preflight checks
    if not FRPS_BIN.exists():
        log(f"frps binary not found: {FRPS_BIN}", RED)
        sys.exit(1)
    if not XFRC_BIN.exists():
        log(f"xfrpc binary not found: {XFRC_BIN}", RED)
        log("  Run: cd xfrpc && cmake --build build -j$(nproc)", YELLOW)
        sys.exit(1)

    log(f"\n{BOLD}xfrpc E2E Proxy Test Suite{RESET}")
    log(f"  Scenarios: {', '.join(requested)}")
    log(f"  frps:      {FRPS_BIN}")
    log(f"  xfrpc:     {XFRC_BIN}")
    log(f"  echo port: {ECHO_PORT}")

    results = {}
    try:
        for name in requested:
            ok = run_scenario(name)
            results[name] = ok
    except KeyboardInterrupt:
        log("\nInterrupted.", YELLOW)
    finally:
        cleanup_all()

    # Summary
    log(f"\n{'='*60}", BOLD)
    log(f"  TEST RESULTS", BOLD)
    log(f"{'='*60}", BOLD)
    all_pass = True
    for name in requested:
        ok = results.get(name, False)
        status = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        log(f"  {name:8s}  {SCENARIOS[name]['desc']:30s}  {status}")
        if not ok:
            all_pass = False

    log(f"\n  Overall: {'ALL PASSED' if all_pass else 'SOME FAILED'}",
        GREEN if all_pass else RED)
    log(f"{'='*60}\n", BOLD)
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
