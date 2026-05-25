"""Pure-function correlation: ``facts → host records + change events``.

No network I/O. No subprocess calls. Inputs are scanner-produced ``Fact`` objects
plus a ``Storage`` handle; outputs are DB mutations and a list of ``Event``s.
This makes the entire correlation surface unit-testable with hand-built fact
lists — see ``tests/unit/test_correlation.py``.

T11: host upsert + ``host.new`` event emission.
T12 will add ``port.opened`` / ``port.closed`` (this file will grow).
T13 will add ``ip.changed`` + per-scan ``HostSnapshot`` insertion.
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from netmap.models import (
    DeviceTypeFact,
    Event,
    Fact,
    Host,
    HostKey,
    HostnameFact,
    MacFact,
    OsFact,
    PortFact,
)
from netmap.oui import lookup_vendor
from netmap.storage import Storage


def correlate(
    facts: Iterable[Fact],
    db: Storage,
    scan_id: int,
    *,
    now: datetime | None = None,
) -> list[Event]:
    """Merge scanner-emitted facts into host records and emit change events."""
    now = now or datetime.now(tz=UTC)
    events: list[Event] = []

    by_key: dict[HostKey, list[Fact]] = {}
    for f in facts:
        key = _key_for(f)
        if key is None:
            continue
        by_key.setdefault(key, []).append(f)

    for key, host_facts in by_key.items():
        existing_id = _find_existing_host_id(db, key)
        host_dto = _build_host_dto(key, host_facts, now)
        updated = db.upsert_host(host_dto)

        if existing_id is None:
            events.append(Event(
                ts=now, scan_id=scan_id, host_id=updated.id, kind="host.new",
                payload={"ip": updated.primary_ip, "mac": updated.mac},
            ))

    for ev in events:
        db.insert_event(ev)

    return events


def _key_for(f: Fact) -> HostKey | None:
    if isinstance(f, MacFact):
        return HostKey(mac=f.mac, ip=f.ip)
    if isinstance(f, PortFact | OsFact | HostnameFact | DeviceTypeFact):
        return f.host_key
    return None


def _find_existing_host_id(db: Storage, key: HostKey) -> int | None:
    if key.mac:
        row = db._conn.execute("SELECT id FROM host WHERE mac=?", (key.mac,)).fetchone()
        if row:
            return int(row[0])
    row = db._conn.execute(
        "SELECT id FROM host WHERE mac IS NULL AND primary_ip=?", (key.ip,)
    ).fetchone()
    return int(row[0]) if row else None


def _build_host_dto(key: HostKey, facts: list[Fact], now: datetime) -> Host:
    hostname: str | None = None
    os_family: str | None = None
    os_detail: str | None = None
    device_type: str | None = None
    for f in facts:
        if isinstance(f, HostnameFact):
            hostname = f.hostname
        elif isinstance(f, OsFact):
            os_family = f.family or os_family
            os_detail = f.detail or os_detail
        elif isinstance(f, DeviceTypeFact):
            device_type = f.device_type

    vendor = lookup_vendor(key.mac) if key.mac else None

    return Host(
        mac=key.mac,
        primary_ip=key.ip,
        hostname=hostname,
        vendor=vendor,
        os_family=os_family,
        os_detail=os_detail,
        device_type=device_type,
        first_seen=now,
        last_seen=now,
    )
