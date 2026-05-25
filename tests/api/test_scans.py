"""GET /api/v1/scans — list scans with filters."""
from __future__ import annotations

from datetime import UTC, datetime

from netmap.models import Scan, Subnet


def _now():
    return datetime.now(tz=UTC)


def _seed_subnet(storage, cidr: str = "192.168.1.0/24") -> None:
    storage.insert_subnet(Subnet(
        cidr=cidr, source="config", enabled=True,
        hop_distance=0, first_seen=_now(),
    ))


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


def test_post_scan_with_explicit_targets_returns_scan_id(client, storage, monkeypatch):
    _seed_subnet(storage)

    async def fake_maybe_run(**kwargs):
        return 42
    monkeypatch.setattr("netmap.server.routes.maybe_run", fake_maybe_run)

    r = client.post(
        "/api/v1/scans",
        json={"mode": "discover", "targets": ["192.168.1.0/24"]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["scan_id"] == 42
    assert body["accepted_targets"] == ["192.168.1.0/24"]


def test_post_scan_defaults_to_enabled_subnets_when_targets_omitted(client, storage, monkeypatch):
    _seed_subnet(storage, cidr="10.0.0.0/24")

    captured: dict = {}
    async def fake_maybe_run(*, mode, targets, **kwargs):
        captured["targets"] = [str(t) for t in targets]
        return 7
    monkeypatch.setattr("netmap.server.routes.maybe_run", fake_maybe_run)

    r = client.post("/api/v1/scans", json={"mode": "default"})
    assert r.status_code == 200
    assert captured["targets"] == ["10.0.0.0/24"]


def test_post_scan_rejects_invalid_cidr_with_409(client, monkeypatch):
    async def fake_maybe_run(**kwargs):  # never reached
        return None
    monkeypatch.setattr("netmap.server.routes.maybe_run", fake_maybe_run)

    r = client.post(
        "/api/v1/scans",
        json={"mode": "discover", "targets": ["0.0.0.0/8"]},
    )
    assert r.status_code == 409
    assert "deny_cidrs" in r.json()["detail"]


def test_post_scan_returns_409_when_target_already_in_flight(
    client, storage, monkeypatch, in_flight,
):
    _seed_subnet(storage)
    in_flight.add(("discover", "192.168.1.0/24"))

    async def fake_maybe_run(**kwargs):  # never reached
        return None
    monkeypatch.setattr("netmap.server.routes.maybe_run", fake_maybe_run)

    r = client.post(
        "/api/v1/scans",
        json={"mode": "discover", "targets": ["192.168.1.0/24"]},
    )
    assert r.status_code == 409
    assert "already running" in r.json()["detail"]


def test_post_scan_400_when_no_targets_and_no_enabled_subnets(client, monkeypatch):
    async def fake_maybe_run(**kwargs):
        return None
    monkeypatch.setattr("netmap.server.routes.maybe_run", fake_maybe_run)

    r = client.post("/api/v1/scans", json={"mode": "discover"})
    assert r.status_code == 400
    assert "no targets" in r.json()["detail"]
