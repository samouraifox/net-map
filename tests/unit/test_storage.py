from datetime import UTC, datetime

import pytest

from netmap.models import Host, Subnet
from netmap.storage import Storage

EXPECTED_TABLES = {
    "host", "host_ip", "subnet", "port", "edge",
    "scan", "host_snapshot", "event",
}


@pytest.fixture
def db() -> Storage:
    return Storage(":memory:")


class TestSchema:
    def test_tables_exist(self, db: Storage) -> None:
        rows = db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        names = {r[0] for r in rows}
        assert EXPECTED_TABLES.issubset(names)

    def test_idempotent_init(self, db: Storage) -> None:
        db._init_schema()
        rows = db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        assert len(rows) >= len(EXPECTED_TABLES)

    def test_mac_unique_partial_index(self, db: Storage) -> None:
        rows = db._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name='uq_host_mac'"
        ).fetchall()
        assert rows, "expected partial unique index uq_host_mac"
        assert "WHERE mac IS NOT NULL" in rows[0][0]


T0 = datetime(2026, 5, 25, 10, 0, tzinfo=UTC)
T1 = datetime(2026, 5, 25, 10, 1, tzinfo=UTC)


def _host(ip: str, mac: str | None = "aa:bb:cc:dd:ee:01") -> Host:
    return Host(mac=mac, primary_ip=ip, first_seen=T0, last_seen=T0)


class TestSubnet:
    def test_insert_and_lookup(self, db: Storage) -> None:
        s = Subnet(cidr="192.168.1.0/24", source="config", first_seen=T0)
        row_id = db.insert_subnet(s)
        assert isinstance(row_id, int)
        got = db.get_subnet_by_cidr("192.168.1.0/24")
        assert got is not None
        assert got.id == row_id

    def test_idempotent_insert(self, db: Storage) -> None:
        s = Subnet(cidr="10.0.0.0/24", source="config", first_seen=T0)
        first = db.insert_subnet(s)
        second = db.insert_subnet(s)
        assert first == second


class TestHostUpsert:
    def test_insert_new_host(self, db: Storage) -> None:
        h = db.upsert_host(_host("192.168.1.5"))
        assert h.id is not None
        assert h.primary_ip == "192.168.1.5"

    def test_upsert_existing_by_mac_updates_last_seen(self, db: Storage) -> None:
        first = db.upsert_host(_host("192.168.1.5"))
        updated = db.upsert_host(
            _host("192.168.1.5").model_copy(update={"last_seen": T1})
        )
        assert updated.id == first.id
        assert updated.last_seen == T1

    def test_upsert_by_ip_when_no_mac(self, db: Storage) -> None:
        h = db.upsert_host(_host("10.0.0.7", mac=None))
        assert h.id is not None

    def test_ip_change_for_known_mac(self, db: Storage) -> None:
        first = db.upsert_host(_host("192.168.1.5"))
        moved = db.upsert_host(
            _host("192.168.1.99").model_copy(update={"last_seen": T1})
        )
        assert moved.id == first.id
        assert moved.primary_ip == "192.168.1.99"
        ips = db.list_host_ips(first.id)
        assert {row["ip"] for row in ips} == {"192.168.1.5", "192.168.1.99"}

    def test_mac_discovery_merges_records(self, db: Storage) -> None:
        # Earlier scan saw IP only (across-router, no MAC)
        ip_only = db.upsert_host(_host("192.168.1.5", mac=None))
        # Later scan from the actual subnet learns the MAC
        with_mac = db.upsert_host(
            _host("192.168.1.5", mac="aa:bb:cc:dd:ee:01")
            .model_copy(update={"last_seen": T1})
        )
        assert with_mac.id == ip_only.id
        assert with_mac.mac == "aa:bb:cc:dd:ee:01"
