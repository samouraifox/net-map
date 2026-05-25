"""Shared fixtures for API tests.

The `client` fixture builds a FastAPI app wired to an in-memory Storage and
a fresh AsyncBus, with the scan loop scanner factory replaced by a no-op so
real subprocess calls never happen.
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from netmap.config import Config, ScanCfg
from netmap.server.app import create_app
from netmap.server.events import AsyncBus
from netmap.storage import Storage


@pytest.fixture
def storage() -> Storage:
    return Storage(":memory:")


@pytest.fixture
def bus() -> AsyncBus:
    return AsyncBus()


@pytest.fixture
def in_flight() -> set[tuple[str, str]]:
    return set()


@pytest.fixture
def cfg() -> Config:
    # Long intervals so the loop doesn't fire during a test.
    return Config(scan=ScanCfg(interval_s=99_999, default_scan_interval_s=99_999))


@pytest.fixture
def client(cfg, storage, bus, in_flight):
    stop = asyncio.Event()
    app = create_app(
        cfg=cfg, db=storage, bus=bus, in_flight=in_flight, stop=stop,
    )
    with TestClient(app) as c:
        yield c
