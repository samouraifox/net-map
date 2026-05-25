"""Foreground asyncio scan loop + per-scan dispatcher.

`scan_loop` runs while the process is alive and ticks on `cfg.scan.interval_s`.
`maybe_run` opens a scan row, registers the (mode, target_signature) pair in
the shared in-flight set, and dispatches the actual scan work as a background
task. Both the periodic loop and the API's `POST /scans` go through this
single funnel.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import IPv4Network

from netmap.config import Config
from netmap.correlation import correlate
from netmap.models import Event, Fact, Scan
from netmap.scanner.arp_scanner import ArpScanner
from netmap.scanner.base import ActiveScanner, ScanMode
from netmap.scanner.nmap_scanner import NmapScanner
from netmap.scanner.safety import SafetyError, SafetyPolicy, validate_target
from netmap.server.events import AsyncBus
from netmap.storage import Storage

logger = logging.getLogger("netmap.loop")

ScannerFactory = Callable[[Config, ScanMode], list[ActiveScanner]]


def default_scanners(cfg: Config, mode: ScanMode) -> list[ActiveScanner]:
    """Real scanner stack: nmap + scapy ARP. ARP is link-local only;
    nmap discover sweep handles everything past the local subnet."""
    return [
        NmapScanner(
            default_host_timeout=cfg.scan.default_scan_host_timeout,
            deep_host_timeout=cfg.scan.deep_scan_host_timeout,
        ),
        ArpScanner(iface=None),
    ]


def _signature(targets: list[IPv4Network]) -> str:
    return ",".join(sorted(str(t) for t in targets))


async def maybe_run(
    *,
    mode: ScanMode,
    targets: list[IPv4Network],
    db: Storage,
    bus: AsyncBus,
    cfg: Config,
    in_flight: set[tuple[str, str]],
    source: str,
    scanners_for_mode: ScannerFactory = default_scanners,
) -> int | None:
    """Open a scan row, dispatch the work as a background task, return scan_id.

    Returns None if (mode, target_signature) is already in flight — in which
    case a `scan.skipped` event is published and a status='skipped' scan row
    is written for the audit trail.
    """
    now = datetime.now(tz=UTC)
    sig = _signature(targets)
    key = (mode.value, sig)

    if key in in_flight:
        scan_id = db.start_scan(Scan(
            started_at=now, source=source, target=sig, mode=mode.value,
            status="skipped", hosts_seen=0,
            notes="another scan with the same target/mode is already running",
        ))
        db.finish_scan(scan_id, ended_at=now, status="skipped", hosts_seen=0)
        await bus.publish(Event(
            ts=now, scan_id=scan_id, kind="scan.skipped",
            payload={"reason": "already running", "mode": mode.value, "target": sig},
        ))
        return None

    in_flight.add(key)
    scan_id = db.start_scan(Scan(
        started_at=now, source=source, target=sig, mode=mode.value,
        status="running", hosts_seen=0,
    ))
    await bus.publish(Event(
        ts=now, scan_id=scan_id, kind="scan.started",
        payload={"mode": mode.value, "target": sig},
    ))

    asyncio.create_task(_run_scan_work(
        mode=mode, targets=targets, scan_id=scan_id,
        db=db, bus=bus, cfg=cfg, in_flight=in_flight, key=key,
        scanners=scanners_for_mode(cfg, mode),
    ))
    return scan_id


async def _run_scan_work(
    *,
    mode: ScanMode,
    targets: list[IPv4Network],
    scan_id: int,
    db: Storage,
    bus: AsyncBus,
    cfg: Config,
    in_flight: set[tuple[str, str]],
    key: tuple[str, str],
    scanners: list[ActiveScanner],
) -> None:
    started = time.monotonic()
    try:
        facts: list[Fact] = []
        for target in targets:
            for scanner in scanners:
                async for fact in scanner.scan(target, mode):
                    facts.append(fact)
        now = datetime.now(tz=UTC)
        observed = (
            [str(t) for t in targets]
            if mode in (ScanMode.DEFAULT, ScanMode.DEEP)
            else []
        )
        events = correlate(
            facts, db, scan_id, now=now, observed_subnets=observed,
        )
        for ev in events:
            await bus.publish(ev)

        hosts = db._conn.execute("SELECT COUNT(*) FROM host").fetchone()[0]
        db.finish_scan(
            scan_id, ended_at=now, status="ok", hosts_seen=int(hosts),
        )
        await bus.publish(Event(
            ts=now, scan_id=scan_id, kind="scan.ok",
            payload={"hosts_seen": int(hosts),
                     "duration_s": round(time.monotonic() - started, 3)},
        ))
    except Exception as exc:
        now = datetime.now(tz=UTC)
        logger.exception("scan %s failed", scan_id)
        db.finish_scan(scan_id, ended_at=now, status="error", hosts_seen=0)
        await bus.publish(Event(
            ts=now, scan_id=scan_id, kind="scan.error",
            payload={"error": str(exc), "mode": mode.value,
                     "target": _signature(targets)},
        ))
    finally:
        in_flight.discard(key)


async def scan_loop(
    db: Storage,
    bus: AsyncBus,
    stop: asyncio.Event,
    cfg: Config,
    in_flight: set[tuple[str, str]],
) -> None:
    """Tick `discover` every `cfg.scan.interval_s` and `default` every
    `cfg.scan.default_scan_interval_s`. Exits when `stop` is set."""
    policy = SafetyPolicy(
        deny_cidrs=tuple(cfg.safety.deny_cidrs),
        allow_public_scan=cfg.safety.allow_public_scan,
        max_target_hosts=cfg.safety.max_target_hosts,
        max_hop_distance=cfg.safety.max_hop_distance,
    )
    last_default = 0.0
    while not stop.is_set():
        subnets = [s for s in db.list_subnets() if s.enabled]
        raw_targets: list[IPv4Network] = []
        for s in subnets:
            try:
                raw_targets.append(IPv4Network(s.cidr))
            except (ValueError, TypeError):
                logger.warning("skipping unparseable subnet cidr: %s", s.cidr)

        targets: list[IPv4Network] = []
        now = datetime.now(tz=UTC)
        for t in raw_targets:
            try:
                validate_target(str(t), policy, override_deny=False)
                targets.append(t)
            except SafetyError as exc:
                logger.warning("scan_loop: skipping rejected target %s: %s", t, exc)
                await bus.publish(Event(
                    ts=now, scan_id=None, kind="scan.error",
                    payload={"error": str(exc), "mode": "discover", "target": str(t)},
                ))

        if targets:
            await maybe_run(
                mode=ScanMode.DISCOVER, targets=targets,
                db=db, bus=bus, cfg=cfg, in_flight=in_flight,
                source="loop.discover",
            )
            if time.monotonic() - last_default > cfg.scan.default_scan_interval_s:
                asyncio.create_task(maybe_run(
                    mode=ScanMode.DEFAULT, targets=targets,
                    db=db, bus=bus, cfg=cfg, in_flight=in_flight,
                    source="loop.default",
                ))
                last_default = time.monotonic()

        # TimeoutError is the expected control flow: it means "interval
        # elapsed without a stop signal — go around the loop again".
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=cfg.scan.interval_s)
