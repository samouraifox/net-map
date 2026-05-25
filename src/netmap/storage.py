"""SQLite storage layer.

Wraps `sqlite3`. The schema is created on instantiation. All public methods are
synchronous; the async scan loop wraps them with ``asyncio.to_thread`` where
needed (called from `loop.py` in M2).
"""
from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

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
