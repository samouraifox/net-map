"""Pure-function correlation: ``facts → host records + change events``.

No network I/O. No subprocess calls. Inputs are scanner-produced ``Fact`` objects
plus a ``Storage`` handle; outputs are DB mutations and a list of ``Event``s.
This makes the entire correlation surface unit-testable with hand-built fact
lists — see ``tests/unit/test_correlation.py``.

T11: host upsert + ``host.new`` event emission.
T12: ``port.opened`` / ``port.closed`` events.
T13: ``ip.changed`` event + per-scan ``HostSnapshot`` insertion.
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network

from netmap.models import (
    DeviceTypeFact,
    Event,
    Fact,
    Host,
    HostKey,
    HostnameFact,
    HostSnapshot,
    MacFact,
    OsFact,
    Port,
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
    observed_subnets: list[str] | None = None,
) -> list[Event]:
    """Merge scanner-emitted facts into host records and emit change events.

    Args:
        facts: scanner-emitted observations to merge.
        db: storage handle for upserts, snapshot writes, and event recording.
        scan_id: the row in ``scan`` to attribute these events to.
        now: timestamp for first_seen / last_seen / event ts. Defaults to UTC now.
        observed_subnets: list of CIDRs the scan actually probed for *ports*.
            Closure detection (``port.closed`` events) only fires for hosts
            whose primary_ip falls inside one of these CIDRs. **Callers MUST
            pass an empty list (or None) for discover-only scans** — passing
            a non-empty list signals "I just probed these subnets' ports;
            close anything I didn't re-observe." Getting this wrong will
            emit spurious port.closed events for hosts the scan never
            actually inspected.

    Returns:
        the list of events emitted (also inserted into the ``event`` table).
    """
    now = now or datetime.now(tz=UTC)
    observed_nets = [IPv4Network(c) for c in (observed_subnets or [])]
    events: list[Event] = []

    by_key: dict[HostKey, list[Fact]] = {}
    for f in facts:
        key = _key_for(f)
        if key is None:
            continue
        by_key.setdefault(key, []).append(f)

    for key, host_facts in by_key.items():
        existing = _find_existing_host(db, key)
        host_dto = _build_host_dto(key, host_facts, now)
        updated = db.upsert_host(host_dto)
        # `upsert_host` returns the canonical re-read row; id is non-None.
        assert updated.id is not None

        if existing is None:
            events.append(Event(
                ts=now, scan_id=scan_id, host_id=updated.id, kind="host.new",
                payload={"ip": updated.primary_ip, "mac": updated.mac},
            ))
        elif existing.primary_ip != updated.primary_ip:
            events.append(Event(
                ts=now, scan_id=scan_id, host_id=updated.id, kind="ip.changed",
                payload={"old": existing.primary_ip, "new": updated.primary_ip},
            ))

        events.extend(_apply_ports(
            db, updated, host_facts, scan_id, now, observed_nets,
        ))

        # Snapshot the host's post-update state (after _apply_ports has run).
        open_ports = [
            {"proto": p.protocol, "port": p.number,
             "svc": p.service, "ver": p.version}
            for p in db.list_ports(updated.id, only_open=True)
        ]
        db.insert_snapshot(HostSnapshot(
            scan_id=scan_id, host_id=updated.id, ip=updated.primary_ip,
            hostname=updated.hostname, os_detail=updated.os_detail,
            device_type=updated.device_type, open_ports=open_ports,
            captured_at=now,
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


def _find_existing_host(db: Storage, key: HostKey) -> Host | None:
    if key.mac:
        h = db._find_host_by_mac(key.mac)
        if h:
            return h
    return db._find_host_by_ip(key.ip)


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


def _apply_ports(
    db: Storage,
    host: Host,
    facts: list[Fact],
    scan_id: int,
    now: datetime,
    observed_nets: list[IPv4Network],
) -> list[Event]:
    """Apply port facts for one host; emit port.opened / port.closed events."""
    events: list[Event] = []
    seen: set[tuple[str, int]] = set()

    # Snapshot the host's currently-open ports BEFORE upserting any new ones,
    # so port.opened detection uses the pre-scan state.
    existing_open = {
        (p.protocol, p.number) for p in db.list_ports(host.id, only_open=True)
    }

    for f in facts:
        if not isinstance(f, PortFact):
            continue
        seen.add((f.proto, f.port))
        db.upsert_port(Port(
            host_id=host.id, protocol=f.proto, number=f.port, state=f.state,
            service=f.service, version=f.version,
            first_seen=now, last_seen=now,
        ))
        if (f.proto, f.port) not in existing_open and f.state == "open":
            events.append(Event(
                ts=now, scan_id=scan_id, host_id=host.id, kind="port.opened",
                payload={
                    "proto": f.proto, "port": f.port,
                    "service": f.service, "version": f.version,
                },
            ))

    # Closure detection requires the host's primary_ip to fall within one of
    # the ``observed_nets``. A discover-only scan must omit ``observed_subnets``
    # (or pass an empty list) so it cannot emit spurious closures. A port-aware
    # scan passes the subnets it actually probed, which both:
    #   - gates ARP-only scans (no observed_nets → no closures), and
    #   - prevents a scan of subnet A from closing ports on subnet B.
    if _host_in_observed(host, observed_nets):
        for p in db.list_ports(host.id, only_open=True):
            if (p.protocol, p.number) not in seen:
                db.close_port(host.id, p.protocol, p.number)
                events.append(Event(
                    ts=now, scan_id=scan_id, host_id=host.id, kind="port.closed",
                    payload={"proto": p.protocol, "port": p.number},
                ))

    return events


def _host_in_observed(host: Host, observed_nets: list[IPv4Network]) -> bool:
    if not observed_nets:
        return False
    try:
        ip = IPv4Address(host.primary_ip)
    except (ValueError, TypeError):
        return False
    return any(ip in n for n in observed_nets)
