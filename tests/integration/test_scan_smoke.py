"""End-to-end smoke test.

Boots a Python HTTP server on a random localhost port, invokes ``netmap scan``
against ``127.0.0.1/32`` in ``default`` mode, asserts the host + port land in
the DB. Requires the ``nmap`` binary and root/CAP_NET_RAW for SYN scans;
skipped otherwise.
"""
from __future__ import annotations

import http.server
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _can_run_nmap() -> bool:
    if shutil.which("nmap") is None:
        return False
    return os.geteuid() == 0


@pytest.fixture
def http_server() -> Iterator[int]:
    port = _free_port()
    handler = http.server.SimpleHTTPRequestHandler
    srv = socketserver.TCPServer(("127.0.0.1", port), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()


@pytest.mark.skipif(not _can_run_nmap(), reason="nmap not available or not root")
def test_default_scan_finds_local_http(tmp_path: Path, http_server: int) -> None:
    db = tmp_path / "smoke.db"
    cfg = tmp_path / "config.toml"

    proc = subprocess.run(
        [
            sys.executable, "-m", "netmap", "scan",
            "--target", "127.0.0.1/32",
            "--mode", "default",
            "--allow-loopback",
            "--db", str(db),
            "--config", str(cfg),
        ],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr

    import sqlite3
    conn = sqlite3.connect(str(db))
    ports = conn.execute("SELECT number FROM port WHERE state='open'").fetchall()
    assert (http_server,) in ports, f"expected open port {http_server} in {ports}"
