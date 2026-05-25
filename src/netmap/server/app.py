"""FastAPI app factory + lifespan + high-level `run()` entry.

`create_app` is the test-friendly seam: it takes all dependencies as keyword
args. `run()` is the production wiring used by `netmap up` — it builds the
real Storage / AsyncBus / etc, runs privilege/bootstrap, and hands off to
uvicorn.
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from netmap.config import Config
from netmap.scanner.loop import scan_loop
from netmap.server import privilege, subnet_bootstrap
from netmap.server.events import AsyncBus
from netmap.storage import Storage

logger = logging.getLogger("netmap.server")


def create_app(
    *,
    cfg: Config,
    db: Storage,
    bus: AsyncBus,
    in_flight: set[tuple[str, str]],
    stop: asyncio.Event,
) -> FastAPI:
    """Build a FastAPI app. The lifespan owns the scan-loop task."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        loop_task = asyncio.create_task(
            scan_loop(db, bus, stop, cfg, in_flight),
            name="netmap.scan_loop",
        )
        app.state.netmap_loop_task = loop_task
        try:
            yield
        finally:
            stop.set()
            try:
                await asyncio.wait_for(loop_task, timeout=3)
            except TimeoutError:
                logger.warning("scan loop did not stop within 3s; cancelling")
                loop_task.cancel()

    app = FastAPI(
        title="net-map",
        version="0.2.0",
        lifespan=lifespan,
    )
    app.state.cfg = cfg
    app.state.db = db
    app.state.bus = bus
    app.state.in_flight = in_flight
    # Routes registered in Tasks 15-19 will be added below this comment.
    return app


def run(
    cfg: Config,
    *,
    db_path: Path,
    cli_targets: list[str] | None = None,
) -> None:
    """Production entry. Runs privilege checks + bootstrap, then hands off to uvicorn."""
    import uvicorn

    privilege.check_or_exit(cfg)

    db = Storage(str(db_path))
    subnet_bootstrap.run(db, override=cli_targets)

    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    stop = asyncio.Event()
    app = create_app(cfg=cfg, db=db, bus=bus, in_flight=in_flight, stop=stop)

    uvicorn.run(
        app,
        host=cfg.server.bind,
        port=cfg.server.port,
        log_level="info",
    )
