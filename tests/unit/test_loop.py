"""scan_loop and maybe_run — dispatching, in-flight guard, error containment."""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from ipaddress import IPv4Network
from typing import ClassVar

import pytest

from netmap.config import Config, ScanCfg
from netmap.models import Fact, MacFact, Subnet
from netmap.scanner.base import ScanMode
from netmap.scanner.loop import maybe_run, scan_loop
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


@pytest.mark.asyncio
async def test_scan_loop_dispatches_discover_each_tick_until_stop_is_set(monkeypatch):
    db = Storage(":memory:")
    _seed_subnet(db)
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    stop = asyncio.Event()

    cfg = Config(scan=ScanCfg(interval_s=1, default_scan_interval_s=99_999))

    calls: list[ScanMode] = []
    async def fake_maybe_run(*, mode, **_):
        calls.append(mode)
        return 1
    monkeypatch.setattr("netmap.scanner.loop.maybe_run", fake_maybe_run)

    task = asyncio.create_task(scan_loop(db, bus, stop, cfg, in_flight))
    await asyncio.sleep(2.2)
    stop.set()
    await asyncio.wait_for(task, timeout=2)

    assert calls.count(ScanMode.DISCOVER) >= 2


@pytest.mark.asyncio
async def test_scan_loop_dispatches_default_after_interval(monkeypatch):
    db = Storage(":memory:")
    _seed_subnet(db)
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    stop = asyncio.Event()

    # discover every 1s; default every 2s
    cfg = Config(scan=ScanCfg(interval_s=1, default_scan_interval_s=2))

    calls: list[ScanMode] = []
    async def fake_maybe_run(*, mode, **_):
        calls.append(mode)
        return 1
    monkeypatch.setattr("netmap.scanner.loop.maybe_run", fake_maybe_run)

    task = asyncio.create_task(scan_loop(db, bus, stop, cfg, in_flight))
    await asyncio.sleep(2.5)
    stop.set()
    await asyncio.wait_for(task, timeout=2)

    assert ScanMode.DEFAULT in calls


@pytest.mark.asyncio
async def test_scan_loop_exits_promptly_on_stop():
    db = Storage(":memory:")
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    stop = asyncio.Event()
    cfg = Config(scan=ScanCfg(interval_s=60, default_scan_interval_s=600))

    task = asyncio.create_task(scan_loop(db, bus, stop, cfg, in_flight))
    await asyncio.sleep(0.1)
    stop.set()
    await asyncio.wait_for(task, timeout=2)
    # task should return without exception
    assert task.done() and task.exception() is None


@pytest.mark.asyncio
async def test_scan_loop_skips_invalid_cidrs_and_publishes_scan_error(monkeypatch):
    db = Storage(":memory:")
    # Insert a CIDR that violates the default deny list (169.254.0.0/16 link-local)
    db.insert_subnet(Subnet(
        cidr="169.254.0.0/16", source="discovered", enabled=True,
        hop_distance=0, first_seen=datetime.now(tz=UTC),
    ))
    db.insert_subnet(Subnet(
        cidr="192.168.1.0/24", source="config", enabled=True,
        hop_distance=0, first_seen=datetime.now(tz=UTC),
    ))
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    stop = asyncio.Event()
    cfg = Config(scan=ScanCfg(interval_s=1, default_scan_interval_s=99_999))

    dispatched: list[list[str]] = []
    async def fake_maybe_run(*, mode, targets, **_):
        dispatched.append([str(t) for t in targets])
        return 1
    monkeypatch.setattr("netmap.scanner.loop.maybe_run", fake_maybe_run)

    sub = bus.subscribe()
    task = asyncio.create_task(scan_loop(db, bus, stop, cfg, in_flight))
    await asyncio.sleep(0.2)
    stop.set()
    await asyncio.wait_for(task, timeout=2)

    # Only the valid CIDR was dispatched to maybe_run.
    assert dispatched, "maybe_run was not called"
    assert all("192.168.1.0/24" in t and "169.254" not in str(t) for t in dispatched[0])

    # A scan.error was published for the rejected CIDR.
    kinds = []
    while not sub.empty():
        ev = sub.get_nowait()
        kinds.append(ev.kind)
    assert "scan.error" in kinds
