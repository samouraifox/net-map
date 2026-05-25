"""Lifespan starts the scan loop on startup and stops it on shutdown."""
from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from netmap.config import Config, ScanCfg
from netmap.server.app import create_app
from netmap.server.events import AsyncBus
from netmap.storage import Storage


def test_lifespan_starts_and_stops_scan_loop():
    db = Storage(":memory:")
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    stop = asyncio.Event()
    cfg = Config(scan=ScanCfg(interval_s=99_999, default_scan_interval_s=99_999))

    app = create_app(cfg=cfg, db=db, bus=bus, in_flight=in_flight, stop=stop)
    with TestClient(app) as _c:
        # Inside the `with`, the lifespan has run startup.
        # The scan loop task must exist and be running.
        loop_task = app.state.netmap_loop_task
        assert loop_task is not None
        assert not loop_task.done()

    # On exit, lifespan shutdown ran — stop was set and the task is done.
    assert stop.is_set()
    assert loop_task.done()
