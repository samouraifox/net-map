"""GET /api/v1/hosts and /api/v1/hosts/{id}."""
from __future__ import annotations

from datetime import UTC, datetime

from netmap.models import Event, Host, Port, Subnet


def _now():
    return datetime.now(tz=UTC)


def _seed(storage):
    h1 = storage.upsert_host(Host(
        mac="aa:bb:cc:dd:ee:01", primary_ip="192.168.1.10",
        hostname="printer-lobby", vendor="Brother",
        first_seen=_now(), last_seen=_now(),
    ))
    h2 = storage.upsert_host(Host(
        mac="aa:bb:cc:dd:ee:02", primary_ip="192.168.1.11",
        hostname="laptop", vendor="Apple",
        first_seen=_now(), last_seen=_now(),
    ))
    storage.upsert_port(Port(
        host_id=h1.id, protocol="tcp", number=9100, state="open",
        first_seen=_now(), last_seen=_now(),
    ))
    storage.insert_subnet(Subnet(
        cidr="192.168.1.0/24", source="config", enabled=True,
        hop_distance=0, first_seen=_now(),
    ))
    storage.insert_event(Event(
        ts=_now(), host_id=h1.id, kind="host.new", payload={"ip": h1.primary_ip},
    ))
    return h1.id, h2.id


def test_get_hosts_returns_summary_with_open_port_count(client, storage):
    h1, h2 = _seed(storage)

    r = client.get("/api/v1/hosts")
    assert r.status_code == 200
    data = r.json()
    by_ip = {row["primary_ip"]: row for row in data}
    assert by_ip["192.168.1.10"]["open_port_count"] == 1
    assert by_ip["192.168.1.10"]["hostname"] == "printer-lobby"
    assert by_ip["192.168.1.11"]["open_port_count"] == 0


def test_get_hosts_filters_by_q(client, storage):
    _seed(storage)
    r = client.get("/api/v1/hosts?q=printer")
    assert r.status_code == 200
    rows = r.json()
    assert [row["primary_ip"] for row in rows] == ["192.168.1.10"]


def test_get_hosts_filters_by_subnet(client, storage):
    h1, _ = _seed(storage)
    sid = storage.get_subnet_by_cidr("192.168.1.0/24").id
    r = client.get(f"/api/v1/hosts?subnet={sid}")
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 2


def test_get_host_detail_returns_ports_history_events(client, storage):
    h1, _ = _seed(storage)
    r = client.get(f"/api/v1/hosts/{h1}")
    assert r.status_code == 200
    body = r.json()
    assert body["host"]["primary_ip"] == "192.168.1.10"
    assert len(body["open_ports"]) == 1
    assert body["open_ports"][0]["number"] == 9100
    assert any(ev["kind"] == "host.new" for ev in body["recent_events"])
    assert body["edges"] == []


def test_get_host_detail_404_on_unknown_id(client):
    r = client.get("/api/v1/hosts/9999")
    assert r.status_code == 404
