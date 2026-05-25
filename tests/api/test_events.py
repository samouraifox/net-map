"""GET /api/v1/events — list events with filters."""
from __future__ import annotations

from datetime import UTC, datetime

from netmap.models import Event


def _now():
    return datetime.now(tz=UTC)


def test_get_events_returns_all_recent_events(client, storage):
    storage.insert_event(Event(ts=_now(), kind="scan.started"))
    storage.insert_event(Event(ts=_now(), kind="host.new"))

    r = client.get("/api/v1/events")
    assert r.status_code == 200
    assert len(r.json()) == 2


def test_get_events_filters_by_kind(client, storage):
    storage.insert_event(Event(ts=_now(), kind="scan.started"))
    storage.insert_event(Event(ts=_now(), kind="host.new"))

    r = client.get("/api/v1/events?kind=host.new")
    assert r.status_code == 200
    rows = r.json()
    assert [row["kind"] for row in rows] == ["host.new"]


def test_get_events_filters_by_since(client, storage):
    early = datetime(2026, 1, 1, tzinfo=UTC)
    late = datetime(2026, 5, 25, tzinfo=UTC)
    storage.insert_event(Event(ts=early, kind="scan.started"))
    storage.insert_event(Event(ts=late, kind="host.new"))

    r = client.get("/api/v1/events?since=2026-03-01T00:00:00%2B00:00")
    assert r.status_code == 200
    rows = r.json()
    assert [row["kind"] for row in rows] == ["host.new"]
