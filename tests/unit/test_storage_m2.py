"""Tests for storage helpers added in M2."""
from __future__ import annotations

from datetime import UTC, datetime

from netmap.models import Subnet
from netmap.storage import Storage


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=UTC)


def test_list_subnets_returns_all_rows_ordered_by_id():
    db = Storage(":memory:")
    db.insert_subnet(Subnet(
        cidr="192.168.1.0/24", source="config", enabled=True,
        hop_distance=0, first_seen=_ts("2026-05-25T10:00:00"),
    ))
    db.insert_subnet(Subnet(
        cidr="10.0.0.0/24", source="discovered", enabled=False,
        hop_distance=1, first_seen=_ts("2026-05-25T10:01:00"),
    ))

    rows = db.list_subnets()

    assert [s.cidr for s in rows] == ["192.168.1.0/24", "10.0.0.0/24"]
    assert rows[0].source == "config" and rows[0].enabled is True
    assert rows[1].source == "discovered" and rows[1].enabled is False
    assert rows[1].hop_distance == 1


from netmap.models import Host, Port


def _make_host(db: Storage, *, mac: str | None, ip: str, hostname: str | None = None,
                vendor: str | None = None) -> int:
    now = _ts("2026-05-25T10:00:00")
    h = db.upsert_host(Host(
        mac=mac, primary_ip=ip, hostname=hostname, vendor=vendor,
        first_seen=now, last_seen=now,
    ))
    assert h.id is not None
    return h.id


def _add_port(db: Storage, host_id: int, port: int, state: str = "open") -> None:
    now = _ts("2026-05-25T10:00:00")
    db.upsert_port(Port(
        host_id=host_id, protocol="tcp", number=port, state=state,
        first_seen=now, last_seen=now,
    ))


def test_list_host_summaries_returns_open_port_count():
    db = Storage(":memory:")
    a = _make_host(db, mac="aa:bb:cc:dd:ee:01", ip="192.168.1.10")
    b = _make_host(db, mac="aa:bb:cc:dd:ee:02", ip="192.168.1.11")
    _add_port(db, a, 22, "open")
    _add_port(db, a, 80, "open")
    _add_port(db, a, 9999, "closed")
    _add_port(db, b, 443, "open")

    rows = db.list_host_summaries()

    by_ip = {r["primary_ip"]: r for r in rows}
    assert by_ip["192.168.1.10"]["open_port_count"] == 2
    assert by_ip["192.168.1.11"]["open_port_count"] == 1


def test_list_host_summaries_filters_by_q_against_hostname_ip_mac_vendor():
    db = Storage(":memory:")
    _make_host(db, mac="aa:bb:cc:dd:ee:01", ip="192.168.1.10",
               hostname="printer-lobby", vendor="Brother Industries")
    _make_host(db, mac="aa:bb:cc:dd:ee:02", ip="192.168.1.11",
               hostname="laptop-aymen", vendor="Apple")

    by_hostname = db.list_host_summaries(q="printer")
    assert [r["primary_ip"] for r in by_hostname] == ["192.168.1.10"]

    by_ip = db.list_host_summaries(q="1.11")
    assert [r["primary_ip"] for r in by_ip] == ["192.168.1.11"]

    by_vendor = db.list_host_summaries(q="apple")
    assert [r["primary_ip"] for r in by_vendor] == ["192.168.1.11"]


def test_list_host_summaries_filters_by_subnet_membership():
    db = Storage(":memory:")
    db.insert_subnet(Subnet(
        cidr="192.168.1.0/24", source="config", enabled=True,
        hop_distance=0, first_seen=_ts("2026-05-25T10:00:00"),
    ))
    sid = db.get_subnet_by_cidr("192.168.1.0/24").id
    _make_host(db, mac="aa:bb:cc:dd:ee:01", ip="192.168.1.10")
    _make_host(db, mac="aa:bb:cc:dd:ee:02", ip="10.0.0.5")

    rows = db.list_host_summaries(subnet_id=sid)

    assert [r["primary_ip"] for r in rows] == ["192.168.1.10"]
