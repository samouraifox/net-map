import pytest

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
