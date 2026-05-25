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
