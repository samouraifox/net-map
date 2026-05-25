"""End-to-end smoke for `netmap up`. Skipped unless nmap is on PATH and the
test process can scan 127.0.0.1 (i.e. root or CAP_NET_RAW)."""
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from contextlib import closing

import httpx
import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("nmap") is None, reason="nmap binary not on PATH",
    ),
    pytest.mark.skipif(
        os.geteuid() != 0, reason="must run as root for raw sockets",
    ),
]


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for(predicate, *, timeout=20, interval=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


@pytest.fixture
def netmap_proc(tmp_path):
    port = _free_port()
    db = tmp_path / "state.db"
    config = tmp_path / "config.toml"
    # Stub config that allows loopback scan via override flag-like mechanism:
    # we wire safety policy by configuring max_target_hosts to allow /32 and
    # we'll POST against 127.0.0.1/32 with the routes' `confirm=true` arg.
    # But default deny_cidrs blocks 127.0.0.0/8 — for the smoke we strip it.
    config.write_text(
        "[server]\nbind = \"127.0.0.1\"\nport = " + str(port) + "\n"
        "[safety]\ndeny_cidrs = []\n"
    )
    env = {**os.environ}
    proc = subprocess.Popen(
        [sys.executable, "-m", "netmap", "up",
         "--db", str(db), "--config", str(config), "--no-open"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
    )
    base = f"http://127.0.0.1:{port}"

    def ready():
        try:
            httpx.get(base + "/api/v1/subnets", timeout=1)
            return True
        except Exception:
            return False

    if not _wait_for(ready, timeout=20):
        proc.kill()
        raise RuntimeError(
            "netmap up never opened the API:\n" + proc.stderr.read().decode()
        )
    yield base, proc
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_post_scan_triggers_host_new_event_for_loopback(netmap_proc):
    base, proc = netmap_proc

    # Open SSE; collect kinds for 30s while we trigger a scan against 127.0.0.1/32.
    seen_kinds: list[str] = []
    with httpx.stream("GET", base + "/api/v1/stream", timeout=30) as resp:
        r = httpx.post(
            base + "/api/v1/scans",
            json={"mode": "default", "targets": ["127.0.0.1/32"]},
            timeout=5,
        )
        assert r.status_code == 200, r.text

        deadline = time.monotonic() + 30
        for line in resp.iter_lines():
            if time.monotonic() > deadline:
                break
            if not line.startswith("data:"):
                continue
            payload = json.loads(line[len("data:"):].strip())
            seen_kinds.append(payload["kind"])
            if "host.new" in seen_kinds and "scan.ok" in seen_kinds:
                break

    assert "scan.started" in seen_kinds
    assert "scan.ok" in seen_kinds
    assert "host.new" in seen_kinds


def test_sigint_exits_cleanly(netmap_proc):
    _base, proc = netmap_proc
    proc.send_signal(signal.SIGINT)
    try:
        rc = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        pytest.fail("netmap up did not exit within 5s of SIGINT")
    assert rc == 0
