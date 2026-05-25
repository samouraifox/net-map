"""scan_loop and maybe_run — dispatching, in-flight guard, error containment."""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from ipaddress import IPv4Network
from typing import ClassVar

import pytest

from netmap.config import Config
from netmap.models import Fact, MacFact, Subnet
from netmap.scanner.base import ScanMode
from netmap.scanner.loop import maybe_run
from netmap.server.events import AsyncBus
from netmap.storage import Storage


class FakeScanner:
    name: ClassVar[str] = "test.fake"
    def __init__(self, facts: list[Fact], raises: Exception | None = None) -> None:
        self._facts = facts
        self._raises = raises
    async def scan(self, target: IPv4Network, mode: ScanMode) -> AsyncIterator[Fact]:
        if self._raises:
            raise self._raises
        for f in self._facts:
            yield f


def _seed_subnet(db: Storage, cidr: str = "192.168.1.0/24") -> None:
    db.insert_subnet(Subnet(
        cidr=cidr, source="config", enabled=True,
        hop_distance=0, first_seen=datetime.now(tz=UTC),
    ))


async def _collect_events(bus: AsyncBus, expected: int, timeout: float = 2) -> list:
    q = bus.subscribe()
    out = []
    async with asyncio.timeout(timeout):
        while len(out) < expected:
            out.append(await q.get())
    return out


@pytest.mark.asyncio
async def test_maybe_run_opens_scan_row_and_dispatches_work():
    db = Storage(":memory:")
    _seed_subnet(db)
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    fact = MacFact(mac="aa:bb:cc:dd:ee:01", ip="192.168.1.10", src="test.fake")

    sub = bus.subscribe()
    scan_id = await maybe_run(
        mode=ScanMode.DISCOVER,
        targets=[IPv4Network("192.168.1.0/24")],
        db=db, bus=bus, cfg=Config(), in_flight=in_flight,
        source="test",
        scanners_for_mode=lambda _cfg, _mode: [FakeScanner([fact])],
    )
    assert scan_id is not None
    started = await asyncio.wait_for(sub.get(), timeout=1)
    assert started.kind == "scan.started"
    # Let the background task finish
    await asyncio.sleep(0.05)
    saw = []
    while not sub.empty():
        saw.append(sub.get_nowait().kind)
    assert "scan.ok" in saw


@pytest.mark.asyncio
async def test_maybe_run_skips_when_same_target_in_flight():
    db = Storage(":memory:")
    bus = AsyncBus()
    in_flight = {(ScanMode.DISCOVER.value, "192.168.1.0/24")}

    sub = bus.subscribe()
    scan_id = await maybe_run(
        mode=ScanMode.DISCOVER,
        targets=[IPv4Network("192.168.1.0/24")],
        db=db, bus=bus, cfg=Config(), in_flight=in_flight,
        source="test",
        scanners_for_mode=lambda _c, _m: [],
    )
    assert scan_id is None
    skipped = await asyncio.wait_for(sub.get(), timeout=1)
    assert skipped.kind == "scan.skipped"


@pytest.mark.asyncio
async def test_maybe_run_catches_scanner_exception_and_publishes_scan_error():
    db = Storage(":memory:")
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()

    sub = bus.subscribe()
    scan_id = await maybe_run(
        mode=ScanMode.DISCOVER,
        targets=[IPv4Network("192.168.1.0/24")],
        db=db, bus=bus, cfg=Config(), in_flight=in_flight,
        source="test",
        scanners_for_mode=lambda _c, _m: [FakeScanner([], raises=RuntimeError("boom"))],
    )
    assert scan_id is not None

    await asyncio.sleep(0.1)
    kinds: list[str] = []
    while not sub.empty():
        kinds.append(sub.get_nowait().kind)
    assert "scan.error" in kinds

    scan = db.get_scan(scan_id)
    assert scan.status == "error"

    # in_flight set must be cleared so a follow-up can run
    assert in_flight == set()


@pytest.mark.asyncio
async def test_maybe_run_finishes_scan_with_ok_status_on_happy_path():
    db = Storage(":memory:")
    _seed_subnet(db)
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    fact = MacFact(mac="aa:bb:cc:dd:ee:01", ip="192.168.1.10", src="test.fake")

    scan_id = await maybe_run(
        mode=ScanMode.DEFAULT,
        targets=[IPv4Network("192.168.1.0/24")],
        db=db, bus=bus, cfg=Config(), in_flight=in_flight,
        source="test",
        scanners_for_mode=lambda _c, _m: [FakeScanner([fact])],
    )
    assert scan_id is not None
    await asyncio.sleep(0.1)
    assert db.get_scan(scan_id).status == "ok"
    assert in_flight == set()
