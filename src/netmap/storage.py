"""SQLite storage layer.

Wraps `sqlite3`. The schema is created on instantiation. All public methods are
synchronous; the async scan loop wraps them with ``asyncio.to_thread`` where
needed (called from `loop.py` in M2).
"""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from netmap.models import Edge, Event, Host, HostSnapshot, Port, Scan, Subnet


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _ip_in_net_safe(ip: str, net) -> bool:
    from ipaddress import AddressValueError, IPv4Address
    try:
        return IPv4Address(ip) in net
    except (AddressValueError, ValueError):
        return False


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
        # check_same_thread=False because M2's scan loop uses asyncio.to_thread.
        # Callers are expected to serialize writes (the scan loop and CLI both do).
        self._conn = sqlite3.connect(
            str(path), isolation_level=None, check_same_thread=False
        )
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

    def list_subnets(self) -> list[Subnet]:
        rows = self._conn.execute(
            "SELECT id, cidr, label, source, enabled, hop_distance, first_seen "
            "FROM subnet ORDER BY id"
        ).fetchall()
        return [
            Subnet(
                id=r[0], cidr=r[1], label=r[2], source=r[3],
                enabled=bool(r[4]), hop_distance=r[5],
                first_seen=datetime.fromisoformat(r[6]),
            )
            for r in rows
        ]

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

    def get_host(self, host_id: int) -> Host | None:
        row = self._conn.execute(
            self._SELECT_HOST + " WHERE id=?", (host_id,)
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

    def list_host_summaries(
        self,
        *,
        subnet_id: int | None = None,
        q: str | None = None,
    ) -> list[dict]:
        """Return a list of dicts shaped for the GET /hosts API.

        Columns: id, mac, primary_ip, hostname, vendor, device_type, trusted,
        open_port_count, last_seen. The subnet filter matches the host's
        primary_ip against the subnet CIDR via SQLite-side check. The q filter
        is a case-insensitive substring against mac, primary_ip, hostname, vendor.
        """
        sql = (
            "SELECT h.id, h.mac, h.primary_ip, h.hostname, h.vendor, "
            "h.device_type, h.trusted, h.last_seen, "
            "COALESCE(SUM(CASE WHEN p.state='open' THEN 1 ELSE 0 END), 0) "
            "FROM host h LEFT JOIN port p ON p.host_id = h.id "
            "WHERE 1=1"
        )
        params: list[object] = []
        if q:
            sql += (
                " AND (lower(COALESCE(h.mac,''))      LIKE ?"
                "   OR lower(h.primary_ip)            LIKE ?"
                "   OR lower(COALESCE(h.hostname,'')) LIKE ?"
                "   OR lower(COALESCE(h.vendor,''))   LIKE ?)"
            )
            pattern = f"%{q.lower()}%"
            params.extend([pattern, pattern, pattern, pattern])
        sql += " GROUP BY h.id ORDER BY h.id"

        rows = self._conn.execute(sql, params).fetchall()

        result: list[dict] = []
        for r in rows:
            result.append({
                "id": r[0], "mac": r[1], "primary_ip": r[2],
                "hostname": r[3], "vendor": r[4], "device_type": r[5],
                "trusted": bool(r[6]), "last_seen": r[7],
                "open_port_count": int(r[8]),
            })

        if subnet_id is not None:
            cidr_row = self._conn.execute(
                "SELECT cidr FROM subnet WHERE id=?", (subnet_id,)
            ).fetchone()
            if not cidr_row:
                return []
            from ipaddress import IPv4Network
            net = IPv4Network(cidr_row[0])
            result = [
                r for r in result
                if _ip_in_net_safe(r["primary_ip"], net)
            ]
        return result

    def list_host_ips(self, host_id: int) -> list[dict]:
        rows = self._conn.execute(
            "SELECT ip, first_seen, last_seen FROM host_ip WHERE host_id=? "
            "ORDER BY first_seen",
            (host_id,),
        ).fetchall()
        return [
            {"ip": r[0], "first_seen": r[1], "last_seen": r[2]} for r in rows
        ]

    # ---------- port ----------
    def upsert_port(self, p: Port) -> None:
        self._conn.execute(
            "INSERT INTO port(host_id, protocol, number, state, service, version, "
            "first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(host_id, protocol, number) DO UPDATE SET "
            "state=excluded.state, service=COALESCE(excluded.service, service), "
            "version=COALESCE(excluded.version, version), last_seen=excluded.last_seen",
            (
                p.host_id, p.protocol, p.number, p.state, p.service, p.version,
                _iso(p.first_seen), _iso(p.last_seen),
            ),
        )

    def close_port(self, host_id: int, protocol: str, number: int) -> None:
        self._conn.execute(
            "UPDATE port SET state='closed' "
            "WHERE host_id=? AND protocol=? AND number=?",
            (host_id, protocol, number),
        )

    def list_ports(self, host_id: int, *, only_open: bool = False) -> list[Port]:
        sql = (
            "SELECT host_id, protocol, number, state, service, version, "
            "first_seen, last_seen FROM port WHERE host_id=?"
        )
        if only_open:
            sql += " AND state='open'"
        rows = self._conn.execute(sql, (host_id,)).fetchall()
        return [
            Port(
                host_id=r[0], protocol=r[1], number=r[2], state=r[3],
                service=r[4], version=r[5],
                first_seen=datetime.fromisoformat(r[6]),
                last_seen=datetime.fromisoformat(r[7]),
            )
            for r in rows
        ]

    # ---------- edge ----------
    def upsert_edge(self, e: Edge) -> None:
        self._conn.execute(
            "INSERT INTO edge(src_host_id, dst_host_id, kind, weight, last_seen) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(src_host_id, dst_host_id, kind) DO UPDATE SET "
            "weight=weight+1, last_seen=excluded.last_seen",
            (e.src_host_id, e.dst_host_id, e.kind, e.weight, _iso(e.last_seen)),
        )

    def list_edges(self) -> list[Edge]:
        rows = self._conn.execute(
            "SELECT id, src_host_id, dst_host_id, kind, weight, last_seen FROM edge"
        ).fetchall()
        return [
            Edge(
                id=r[0], src_host_id=r[1], dst_host_id=r[2], kind=r[3],
                weight=r[4], last_seen=datetime.fromisoformat(r[5]),
            )
            for r in rows
        ]

    # ---------- scan ----------
    def start_scan(self, s: Scan) -> int:
        cur = self._conn.execute(
            "INSERT INTO scan(started_at, source, target, mode, status, "
            "hosts_seen, notes) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                _iso(s.started_at), s.source, s.target, s.mode, s.status,
                s.hosts_seen, s.notes,
            ),
        )
        return int(cur.lastrowid)

    def finish_scan(
        self, scan_id: int, *, ended_at: datetime, status: str, hosts_seen: int
    ) -> None:
        self._conn.execute(
            "UPDATE scan SET ended_at=?, status=?, hosts_seen=? WHERE id=?",
            (_iso(ended_at), status, hosts_seen, scan_id),
        )

    def get_scan(self, scan_id: int) -> Scan:
        row = self._conn.execute(
            "SELECT id, started_at, ended_at, source, target, mode, status, "
            "hosts_seen, notes FROM scan WHERE id=?",
            (scan_id,),
        ).fetchone()
        return Scan(
            id=row[0],
            started_at=datetime.fromisoformat(row[1]),
            ended_at=datetime.fromisoformat(row[2]) if row[2] else None,
            source=row[3], target=row[4], mode=row[5], status=row[6],
            hosts_seen=row[7], notes=row[8],
        )

    def list_scans(
        self,
        *,
        status: str | None = None,
        since: datetime | None = None,
        limit: int = 50,
    ) -> list[Scan]:
        sql = (
            "SELECT id, started_at, ended_at, source, target, mode, status, "
            "hosts_seen, notes FROM scan WHERE 1=1"
        )
        params: list[object] = []
        if status:
            sql += " AND status=?"
            params.append(status)
        if since:
            sql += " AND started_at >= ?"
            params.append(_iso(since))
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(sql, params).fetchall()
        return [
            Scan(
                id=r[0],
                started_at=datetime.fromisoformat(r[1]),
                ended_at=datetime.fromisoformat(r[2]) if r[2] else None,
                source=r[3], target=r[4], mode=r[5], status=r[6],
                hosts_seen=r[7], notes=r[8],
            )
            for r in rows
        ]

    # ---------- host_snapshot ----------
    def insert_snapshot(self, snap: HostSnapshot) -> None:
        self._conn.execute(
            "INSERT INTO host_snapshot(scan_id, host_id, ip, hostname, "
            "os_detail, device_type, open_ports, captured_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                snap.scan_id, snap.host_id, snap.ip, snap.hostname,
                snap.os_detail, snap.device_type,
                json.dumps(snap.open_ports), _iso(snap.captured_at),
            ),
        )

    def latest_snapshot(self, host_id: int) -> HostSnapshot | None:
        row = self._conn.execute(
            "SELECT id, scan_id, host_id, ip, hostname, os_detail, "
            "device_type, open_ports, captured_at FROM host_snapshot "
            "WHERE host_id=? ORDER BY captured_at DESC LIMIT 1",
            (host_id,),
        ).fetchone()
        if not row:
            return None
        return HostSnapshot(
            id=row[0], scan_id=row[1], host_id=row[2], ip=row[3],
            hostname=row[4], os_detail=row[5], device_type=row[6],
            open_ports=json.loads(row[7]) if row[7] else [],
            captured_at=datetime.fromisoformat(row[8]),
        )

    # ---------- event ----------
    def insert_event(self, e: Event) -> None:
        self._conn.execute(
            "INSERT INTO event(ts, scan_id, host_id, kind, payload) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                _iso(e.ts), e.scan_id, e.host_id, e.kind,
                json.dumps(e.payload) if e.payload else None,
            ),
        )

    def list_events(
        self, *, since: datetime | None = None,
        host_id: int | None = None, limit: int = 500,
    ) -> list[Event]:
        sql = (
            "SELECT id, ts, scan_id, host_id, kind, payload "
            "FROM event WHERE 1=1"
        )
        params: list[object] = []
        if since:
            sql += " AND ts >= ?"
            params.append(_iso(since))
        if host_id:
            sql += " AND host_id = ?"
            params.append(host_id)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [
            Event(
                id=r[0], ts=datetime.fromisoformat(r[1]), scan_id=r[2],
                host_id=r[3], kind=r[4],
                payload=json.loads(r[5]) if r[5] else None,
            )
            for r in rows
        ]

    def list_recent_events(
        self, *, host_id: int, limit: int = 50,
    ) -> list[Event]:
        rows = self._conn.execute(
            "SELECT id, ts, scan_id, host_id, kind, payload FROM event "
            "WHERE host_id=? ORDER BY ts DESC LIMIT ?",
            (host_id, limit),
        ).fetchall()
        return [
            Event(
                id=r[0], ts=datetime.fromisoformat(r[1]), scan_id=r[2],
                host_id=r[3], kind=r[4],
                payload=json.loads(r[5]) if r[5] else None,
            )
            for r in rows
        ]
