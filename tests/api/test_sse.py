"""GET /api/v1/stream — Server-Sent Events.

`TestClient.stream` buffers infinite responses and deadlocks on SSE, so we
spin up a real uvicorn server in a daemon thread and connect with httpx.
"""
from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from contextlib import closing
from datetime import UTC, datetime

import httpx
import pytest
import uvicorn

from netmap.config import Config, ScanCfg
from netmap.models import Event
from netmap.server.app import create_app
from netmap.server.events import AsyncBus
from netmap.storage import Storage


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_server():
    """Spin up uvicorn in a daemon thread; return (base_url, bus, stop_event)."""
    db = Storage(":memory:")
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    stop = asyncio.Event()
    cfg = Config(scan=ScanCfg(interval_s=99_999, default_scan_interval_s=99_999))
    app = create_app(cfg=cfg, db=db, bus=bus, in_flight=in_flight, stop=stop)

    port = _free_port()
    server_config = uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="warning",
        lifespan="on",
    )
    server = uvicorn.Server(server_config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                s.settimeout(0.2)
                s.connect(("127.0.0.1", port))
            break
        except OSError:
            time.sleep(0.05)
    else:
        raise RuntimeError("uvicorn server did not become ready in 5s")

    yield f"http://127.0.0.1:{port}", bus, server

    server.should_exit = True
    thread.join(timeout=5)


def test_sse_returns_event_stream_content_type(live_server):
    base_url, _bus, _server = live_server
    with (
        httpx.Client() as client,
        client.stream("GET", f"{base_url}/api/v1/stream", timeout=3) as response,
    ):
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")


def test_sse_delivers_published_event_to_connected_client(live_server):
    base_url, bus, _server = live_server

    def publish_after(delay: float):
        time.sleep(delay)
        # Schedule the publish on the server's event loop via call_soon_threadsafe.
        # Simpler: just call bus.publish from a thread that uses asyncio.run.
        async def _go():
            await bus.publish(Event(
                ts=datetime.now(tz=UTC), kind="host.new",
                payload={"id": 99},
            ))
        asyncio.run(_go())

    with (
        httpx.Client() as client,
        client.stream("GET", f"{base_url}/api/v1/stream", timeout=5) as response,
    ):
        assert response.status_code == 200
        threading.Thread(target=publish_after, args=(0.2,), daemon=True).start()
        got_event = None
        for line in response.iter_lines():
            if line.startswith("data:"):
                got_event = json.loads(line[len("data:"):].strip())
                break
        assert got_event is not None
        assert got_event["kind"] == "host.new"
        assert got_event["payload"]["id"] == 99
