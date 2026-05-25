"""SQLite storage layer.

Wraps `sqlite3`. The schema is created on instantiation. All public methods are
synchronous; the async scan loop wraps them with ``asyncio.to_thread`` where
needed (called from `loop.py` in M2).
"""
from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from netmap.models import Host, Subnet


def _iso(dt: datetime) -> str:
    return dt.isoformat()

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS host (
  id          INTEGER PRIMARY KEY,
  mac         TEXT,
  primary_ip  TEXT NOT NULL,
  hostname    TEXT,
  vendor      TEXT,
  os_family   TEXT,
  os_detail   TEXT,
  device_type TEXT,
  trusted     INTEGER NOT NULL DEFAULT 0,
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  notes       TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_host_mac ON host(mac) WHERE mac IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_host_ip ON host(primary_ip);

CREATE TABLE IF NOT EXISTS host_ip (
  host_id    INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  ip         TEXT NOT NULL,
  subnet_id  INTEGER REFERENCES subnet(id),
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  PRIMARY KEY (host_id, ip)
);

CREATE TABLE IF NOT EXISTS subnet (
  id            INTEGER PRIMARY KEY,
  cidr          TEXT UNIQUE NOT NULL,
  label         TEXT,
  source        TEXT NOT NULL,
  enabled       INTEGER NOT NULL DEFAULT 1,
  hop_distance  INTEGER NOT NULL DEFAULT 0,
  first_seen    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS port (
  host_id    INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  protocol   TEXT NOT NULL,
  number     INTEGER NOT NULL,
  state      TEXT NOT NULL,
  service    TEXT,
  version    TEXT,
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  PRIMARY KEY (host_id, protocol, number)
);

CREATE TABLE IF NOT EXISTS edge (
  id          INTEGER PRIMARY KEY,
  src_host_id INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  dst_host_id INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  weight      INTEGER NOT NULL DEFAULT 1,
  last_seen   TEXT NOT NULL,
  UNIQUE (src_host_id, dst_host_id, kind)
);

CREATE TABLE IF NOT EXISTS scan (
  id         INTEGER PRIMARY KEY,
  started_at TEXT NOT NULL,
  ended_at   TEXT,
  source     TEXT NOT NULL,
  target     TEXT,
  mode       TEXT,
  status     TEXT NOT NULL,
  hosts_seen INTEGER NOT NULL DEFAULT 0,
  notes      TEXT
);

CREATE TABLE IF NOT EXISTS host_snapshot (
  id          INTEGER PRIMARY KEY,
  scan_id     INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  host_id     INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  ip          TEXT NOT NULL,
  hostname    TEXT,
  os_detail   TEXT,
  device_type TEXT,
  open_ports  TEXT,
  captured_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snap_scan ON host_snapshot(scan_id);
CREATE INDEX IF NOT EXISTS idx_snap_host ON host_snapshot(host_id, captured_at);

CREATE TABLE IF NOT EXISTS event (
  id      INTEGER PRIMARY KEY,
  ts      TEXT NOT NULL,
  scan_id INTEGER REFERENCES scan(id),
  host_id INTEGER REFERENCES host(id),
  kind    TEXT NOT NULL,
  payload TEXT
);
CREATE INDEX IF NOT EXISTS idx_event_ts ON event(ts);
"""


class Storage:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(path), isolation_level=None)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Run a block of statements inside a transaction."""
        self._conn.execute("BEGIN")
        try:
            yield self._conn
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    # ---------- subnet ----------
    def insert_subnet(self, s: Subnet) -> int:
        self._conn.execute(
            "INSERT INTO subnet(cidr, label, source, enabled, hop_distance, first_seen) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(cidr) DO UPDATE SET label=excluded.label",
            (s.cidr, s.label, s.source, int(s.enabled), s.hop_distance, _iso(s.first_seen)),
        )
        row = self._conn.execute(
            "SELECT id FROM subnet WHERE cidr=?", (s.cidr,)
        ).fetchone()
        return int(row[0])

    def get_subnet_by_cidr(self, cidr: str) -> Subnet | None:
        row = self._conn.execute(
            "SELECT id, cidr, label, source, enabled, hop_distance, first_seen "
            "FROM subnet WHERE cidr=?",
            (cidr,),
        ).fetchone()
        if not row:
            return None
        return Subnet(
            id=row[0], cidr=row[1], label=row[2], source=row[3],
            enabled=bool(row[4]), hop_distance=row[5],
            first_seen=datetime.fromisoformat(row[6]),
        )

    # ---------- host ----------
    _SELECT_HOST = (
        "SELECT id, mac, primary_ip, hostname, vendor, os_family, os_detail, "
        "device_type, trusted, first_seen, last_seen, notes FROM host"
    )

    @staticmethod
    def _row_to_host(row: tuple) -> Host:
        return Host(
            id=row[0], mac=row[1], primary_ip=row[2], hostname=row[3], vendor=row[4],
            os_family=row[5], os_detail=row[6], device_type=row[7], trusted=bool(row[8]),
            first_seen=datetime.fromisoformat(row[9]),
            last_seen=datetime.fromisoformat(row[10]), notes=row[11],
        )

    def _find_host_by_mac(self, mac: str) -> Host | None:
        row = self._conn.execute(
            self._SELECT_HOST + " WHERE mac=?", (mac,)
        ).fetchone()
        return self._row_to_host(row) if row else None

    def _find_host_by_ip(self, ip: str) -> Host | None:
        row = self._conn.execute(
            self._SELECT_HOST + " WHERE mac IS NULL AND primary_ip=?", (ip,)
        ).fetchone()
        return self._row_to_host(row) if row else None

    def upsert_host(self, h: Host) -> Host:
        """Upsert a host using MAC-primary / IP-fallback identity.

        If a MAC-less host with the same primary_ip already exists and ``h`` carries
        a MAC, the two records are merged (the IP-only record gets the new MAC).
        """
        with self.tx() as conn:
            existing: Host | None = None
            if h.mac:
                existing = self._find_host_by_mac(h.mac)
                if existing is None:
                    existing = self._find_host_by_ip(h.primary_ip)

            if existing is None:
                cur = conn.execute(
                    "INSERT INTO host(mac, primary_ip, hostname, vendor, os_family, "
                    "os_detail, device_type, trusted, first_seen, last_seen, notes) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        h.mac, h.primary_ip, h.hostname, h.vendor, h.os_family,
                        h.os_detail, h.device_type, int(h.trusted),
                        _iso(h.first_seen), _iso(h.last_seen), h.notes,
                    ),
                )
                host_id = cur.lastrowid
                self._upsert_host_ip(conn, host_id, h.primary_ip, h.first_seen, h.last_seen)
                return h.model_copy(update={"id": host_id})

            new_mac = h.mac or existing.mac
            new_ip = h.primary_ip
            conn.execute(
                "UPDATE host SET mac=?, primary_ip=?, "
                "hostname=COALESCE(?, hostname), vendor=COALESCE(?, vendor), "
                "os_family=COALESCE(?, os_family), os_detail=COALESCE(?, os_detail), "
                "device_type=COALESCE(?, device_type), last_seen=? WHERE id=?",
                (
                    new_mac, new_ip, h.hostname, h.vendor, h.os_family, h.os_detail,
                    h.device_type, _iso(h.last_seen), existing.id,
                ),
            )
            self._upsert_host_ip(conn, existing.id, new_ip, h.first_seen, h.last_seen)

        # After the tx commits, re-read the canonical row.
        result = self._find_host_by_mac(new_mac) if new_mac else self._find_host_by_ip(new_ip)
        assert result is not None
        return result

    def _upsert_host_ip(
        self, conn: sqlite3.Connection, host_id: int, ip: str,
        first_seen: datetime, last_seen: datetime,
    ) -> None:
        conn.execute(
            "INSERT INTO host_ip(host_id, ip, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(host_id, ip) DO UPDATE SET last_seen=excluded.last_seen",
            (host_id, ip, _iso(first_seen), _iso(last_seen)),
        )

    def list_host_ips(self, host_id: int) -> list[dict]:
        rows = self._conn.execute(
            "SELECT ip, first_seen, last_seen FROM host_ip WHERE host_id=? "
            "ORDER BY first_seen",
            (host_id,),
        ).fetchall()
        return [
            {"ip": r[0], "first_seen": r[1], "last_seen": r[2]} for r in rows
        ]
