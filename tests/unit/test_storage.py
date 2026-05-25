from datetime import UTC, datetime

import pytest

from netmap.models import Edge, Event, Host, HostSnapshot, Port, Scan, Subnet
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

    def test_repeated_macless_upsert_is_one_row(self, db: Storage) -> None:
        # Two cross-router observations of the same IP without a MAC should
        # collapse to a single host row (spec §7.1 identity rule).
        first = db.upsert_host(_host("10.0.0.7", mac=None))
        second = db.upsert_host(
            _host("10.0.0.7", mac=None).model_copy(update={"last_seen": T1})
        )
        assert first.id == second.id
        rows = db._conn.execute(
            "SELECT COUNT(*) FROM host WHERE primary_ip=?", ("10.0.0.7",)
        ).fetchone()
        assert rows[0] == 1


class TestPort:
    def test_upsert_new_port(self, db: Storage) -> None:
        host = db.upsert_host(_host("192.168.1.5"))
        p = Port(
            host_id=host.id, protocol="tcp", number=22, state="open",
            service="ssh", version=None, first_seen=T0, last_seen=T0,
        )
        db.upsert_port(p)
        ports = db.list_ports(host.id)
        assert len(ports) == 1
        assert ports[0].number == 22

    def test_upsert_existing_updates_last_seen(self, db: Storage) -> None:
        host = db.upsert_host(_host("192.168.1.5"))
        p = Port(
            host_id=host.id, protocol="tcp", number=22, state="open",
            service="ssh", version=None, first_seen=T0, last_seen=T0,
        )
        db.upsert_port(p)
        db.upsert_port(p.model_copy(update={"last_seen": T1}))
        ports = db.list_ports(host.id)
        assert len(ports) == 1
        assert ports[0].last_seen == T1

    def test_close_port(self, db: Storage) -> None:
        host = db.upsert_host(_host("192.168.1.5"))
        p = Port(
            host_id=host.id, protocol="tcp", number=22, state="open",
            service="ssh", version=None, first_seen=T0, last_seen=T0,
        )
        db.upsert_port(p)
        db.close_port(host.id, "tcp", 22)
        assert db.list_ports(host.id, only_open=True) == []


class TestEdge:
    def test_upsert_edge_creates(self, db: Storage) -> None:
        a = db.upsert_host(_host("10.0.0.1", mac="aa:bb:cc:dd:ee:01"))
        b = db.upsert_host(_host("10.0.0.2", mac="aa:bb:cc:dd:ee:02"))
        e = Edge(
            src_host_id=a.id, dst_host_id=b.id, kind="arp",
            weight=1, last_seen=T0,
        )
        db.upsert_edge(e)
        edges = db.list_edges()
        assert len(edges) == 1

    def test_upsert_edge_increments_weight(self, db: Storage) -> None:
        a = db.upsert_host(_host("10.0.0.1", mac="aa:bb:cc:dd:ee:01"))
        b = db.upsert_host(_host("10.0.0.2", mac="aa:bb:cc:dd:ee:02"))
        e = Edge(
            src_host_id=a.id, dst_host_id=b.id, kind="arp",
            weight=1, last_seen=T0,
        )
        db.upsert_edge(e)
        db.upsert_edge(e.model_copy(update={"last_seen": T1}))
        edges = db.list_edges()
        assert edges[0].weight == 2


class TestScan:
    def test_start_then_finish_scan(self, db: Storage) -> None:
        sid = db.start_scan(Scan(
            started_at=T0, source="active.nmap",
            target="192.168.1.0/24", mode="discover", status="running",
        ))
        db.finish_scan(sid, ended_at=T1, status="ok", hosts_seen=12)
        s = db.get_scan(sid)
        assert s.status == "ok"
        assert s.hosts_seen == 12


class TestSnapshot:
    def test_insert_snapshot_serializes_open_ports(self, db: Storage) -> None:
        host = db.upsert_host(_host("192.168.1.5"))
        sid = db.start_scan(Scan(
            started_at=T0, source="active.nmap", status="running",
        ))
        snap = HostSnapshot(
            scan_id=sid, host_id=host.id, ip="192.168.1.5",
            open_ports=[{"proto": "tcp", "port": 22}],
            captured_at=T0,
        )
        db.insert_snapshot(snap)
        latest = db.latest_snapshot(host.id)
        assert latest is not None
        assert latest.open_ports == [{"proto": "tcp", "port": 22}]


class TestEvent:
    def test_insert_and_list(self, db: Storage) -> None:
        sid = db.start_scan(Scan(
            started_at=T0, source="active.nmap", status="running",
        ))
        host = db.upsert_host(_host("192.168.1.5"))
        evt = Event(
            ts=T0, scan_id=sid, host_id=host.id, kind="host.new",
            payload={"ip": "192.168.1.5"},
        )
        db.insert_event(evt)
        events = db.list_events()
        assert len(events) == 1
        assert events[0].kind == "host.new"
