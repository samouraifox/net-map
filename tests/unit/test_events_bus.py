"""AsyncBus fan-out, slow-consumer drop-oldest, subscribe/unsubscribe lifecycle."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from netmap.models import Event
from netmap.server.events import AsyncBus


def _ev(kind: str, payload: dict | None = None) -> Event:
    return Event(ts=datetime.now(tz=UTC), kind=kind, payload=payload)


@pytest.mark.asyncio
async def test_single_subscriber_receives_published_event():
    bus = AsyncBus()
    q = bus.subscribe()

    await bus.publish(_ev("host.new", {"id": 1}))

    got = await asyncio.wait_for(q.get(), timeout=1)
    assert got.kind == "host.new"
    assert got.payload == {"id": 1}


@pytest.mark.asyncio
async def test_multiple_subscribers_each_get_a_copy():
    bus = AsyncBus()
    q1, q2 = bus.subscribe(), bus.subscribe()

    await bus.publish(_ev("port.opened"))

    e1 = await asyncio.wait_for(q1.get(), timeout=1)
    e2 = await asyncio.wait_for(q2.get(), timeout=1)
    assert e1.kind == "port.opened"
    assert e2.kind == "port.opened"


@pytest.mark.asyncio
async def test_unsubscribe_stops_delivery():
    bus = AsyncBus()
    q = bus.subscribe()
    bus.unsubscribe(q)

    await bus.publish(_ev("ip.changed"))

    assert q.empty()


@pytest.mark.asyncio
async def test_slow_consumer_drops_oldest_when_queue_full():
    bus = AsyncBus(queue_size=3)
    q = bus.subscribe()

    for i in range(5):
        await bus.publish(_ev("scan.ok", {"i": i}))

    # The queue holds at most 3 — and after drop-oldest the surviving events
    # should be the most recent three (i=2, 3, 4).
    survivors = []
    while not q.empty():
        survivors.append(q.get_nowait().payload["i"])
    assert survivors == [2, 3, 4]


@pytest.mark.asyncio
async def test_publish_does_not_block_when_no_subscribers():
    bus = AsyncBus()
    await bus.publish(_ev("scan.started"))  # must not raise / hang
