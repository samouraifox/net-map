"""First-run subnet auto-detection.

Two pure parsers + one `run()` integrator. The parsers are unit-tested
against captured `ip` output; `run()` is exercised at the API/integration
level because it shells out.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
from datetime import UTC, datetime

from netmap.models import Subnet
from netmap.scanner.safety import SafetyError, SafetyPolicy, validate_target
from netmap.storage import Storage

logger = logging.getLogger("netmap.bootstrap")

_RE_DEFAULT_DEV = re.compile(r"^default\s+.*\sdev\s+(\S+)", re.MULTILINE)
_RE_IFACE_ADDR = re.compile(
    r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", re.MULTILINE
)


def parse_ip_route(text: str) -> str | None:
    """Return the iface name from `default via ... dev <iface>` or None."""
    m = _RE_DEFAULT_DEV.search(text)
    return m.group(1) if m else None


def parse_iface_cidr(text: str, iface: str) -> str | None:
    """Return the CIDR of ``iface`` from `ip -o -f inet addr show` output, or None.

    The CIDR returned is the *network* CIDR (e.g. 192.168.1.0/24) not the host
    address-with-mask (192.168.1.42/24).
    """
    for m in _RE_IFACE_ADDR.finditer(text):
        if m.group(1) == iface:
            net = ipaddress.IPv4Network(m.group(2), strict=False)
            return str(net)
    return None


def _detect_local_cidr() -> str | None:
    """Run `ip route show default` + `ip -o -f inet addr show` and combine."""
    try:
        route = subprocess.run(
            ["ip", "route", "show", "default"],
            check=True, capture_output=True, text=True, timeout=5,
        ).stdout
        addrs = subprocess.run(
            ["ip", "-o", "-f", "inet", "addr", "show"],
            check=True, capture_output=True, text=True, timeout=5,
        ).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None

    iface = parse_ip_route(route)
    if not iface:
        return None
    return parse_iface_cidr(addrs, iface)


def run(
    db: Storage,
    *,
    override: list[str] | None = None,
    policy: SafetyPolicy | None = None,
) -> None:
    """Insert the local CIDR into the subnet table.

    Resolution order:
      1. If ``override`` is non-empty, insert each CIDR (validated against
         ``policy`` if provided). Existing rows are upserted.
      2. Else, if the subnet table already has rows, do nothing.
      3. Else, auto-detect via `ip route` + `ip addr`. On detection failure,
         log a warning and insert nothing (the UI shows "waiting for --target").
    """
    now = datetime.now(tz=UTC)

    if override:
        pol = policy or SafetyPolicy()
        for cidr in override:
            try:
                validate_target(cidr, pol, override_deny=False)
            except SafetyError as exc:
                logger.warning("override CIDR rejected: %s", exc)
                continue
            db.insert_subnet(Subnet(
                cidr=cidr, source="config", enabled=True,
                hop_distance=0, first_seen=now,
            ))
        return

    if db.list_subnets():
        return

    detected = _detect_local_cidr()
    if not detected:
        logger.warning(
            "subnet auto-detect failed; start with --target or wait for M3."
        )
        return

    pol = policy or SafetyPolicy()
    try:
        validate_target(detected, pol, override_deny=False)
    except SafetyError as exc:
        logger.warning(
            "auto-detected CIDR %s rejected by safety policy: %s", detected, exc
        )
        return

    db.insert_subnet(Subnet(
        cidr=detected, source="config", enabled=True,
        hop_distance=0, first_seen=now,
    ))
    logger.info("auto-detected subnet: %s", detected)
