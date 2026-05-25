"""GET /api/v1/scans — list scans with filters."""
from __future__ import annotations

from datetime import UTC, datetime

from netmap.models import Scan


def _now():
    return datetime.now(tz=UTC)


def test_get_scans_returns_recent_scans(client, storage):
    storage.start_scan(Scan(
        started_at=_now(), source="cli", target="192.168.1.0/24",
        mode="discover", status="ok", hosts_seen=5,
    ))
    storage.start_scan(Scan(
        started_at=_now(), source="cli", target="192.168.1.0/24",
        mode="default", status="error", hosts_seen=0,
    ))

    r = client.get("/api/v1/scans")
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 2


def test_get_scans_filters_by_status(client, storage):
    storage.start_scan(Scan(
        started_at=_now(), source="cli", target="x", mode="discover",
        status="ok", hosts_seen=0,
    ))
    storage.start_scan(Scan(
        started_at=_now(), source="cli", target="x", mode="discover",
        status="error", hosts_seen=0,
    ))

    r = client.get("/api/v1/scans?status=ok")
    assert r.status_code == 200
    rows = r.json()
    assert all(row["status"] == "ok" for row in rows)


def test_get_scans_respects_limit(client, storage):
    for _ in range(5):
        storage.start_scan(Scan(
            started_at=_now(), source="cli", target="x", mode="discover",
            status="ok", hosts_seen=0,
        ))

    r = client.get("/api/v1/scans?limit=2")
    assert r.status_code == 200
    assert len(r.json()) == 2
