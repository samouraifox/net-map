from datetime import UTC, datetime

import pytest

from netmap.correlation import correlate
from netmap.models import MacFact, Scan
from netmap.storage import Storage

T0 = datetime(2026, 5, 25, 10, 0, tzinfo=UTC)


@pytest.fixture
def db() -> Storage:
    return Storage(":memory:")


@pytest.fixture
def scan_id(db: Storage) -> int:
    return db.start_scan(Scan(started_at=T0, source="active.nmap", status="running"))


class TestNewHost:
    def test_emits_host_new(self, db: Storage, scan_id: int) -> None:
        facts = [MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp")]
        events = correlate(facts, db, scan_id, now=T0)
        kinds = [e.kind for e in events]
        assert "host.new" in kinds

    def test_persists_host_row(self, db: Storage, scan_id: int) -> None:
        correlate(
            [MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp")],
            db, scan_id, now=T0,
        )
        row = db._conn.execute("SELECT mac, primary_ip FROM host").fetchone()
        assert row == ("aa:bb:cc:dd:ee:ff", "192.168.1.5")

    def test_known_host_does_not_emit_new(self, db: Storage, scan_id: int) -> None:
        f = MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp")
        correlate([f], db, scan_id, now=T0)
        sid2 = db.start_scan(Scan(started_at=T0, source="active.nmap", status="running"))
        events = correlate([f], db, sid2, now=T0)
        assert "host.new" not in [e.kind for e in events]

    def test_vendor_filled_from_oui(
        self, db: Storage, scan_id: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import netmap.correlation as corr
        monkeypatch.setattr(corr, "lookup_vendor", lambda mac: "Synology Inc.")
        correlate(
            [MacFact(mac="3c:5a:b4:00:00:01", ip="192.168.1.5", src="active.arp")],
            db, scan_id, now=T0,
        )
        row = db._conn.execute("SELECT vendor FROM host").fetchone()
        assert row[0] == "Synology Inc."
