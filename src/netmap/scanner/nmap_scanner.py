"""nmap binary wrapper + XML parser.

The parser is a pure function over XML text — easy to unit-test against fixture
files. The subprocess wrapper is added in T16.
"""
from __future__ import annotations

import asyncio
import shutil
from collections.abc import AsyncIterator, Iterable
from ipaddress import IPv4Network
from typing import ClassVar
from xml.etree import ElementTree as ET

from netmap.models import (
    DeviceTypeFact,
    Fact,
    HostKey,
    HostnameFact,
    MacFact,
    OsFact,
    PortFact,
)
from netmap.scanner.base import ScanMode


def parse_nmap_xml(xml_text: str) -> Iterable[Fact]:
    """Parse nmap's ``-oX -`` output into a stream of ``Fact``s.

    Only emits facts for hosts whose ``status state="up"``. Closed/filtered
    ports are not emitted as ``PortFact``s (they would just add noise);
    correlation derives port closure from the absence of a fact in a scan
    that observed the host's subnet.
    """
    root = ET.fromstring(xml_text)
    for host_el in root.iterfind("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip: str | None = None
        mac: str | None = None
        vendor: str | None = None
        for addr in host_el.iterfind("address"):
            t = addr.get("addrtype")
            if t == "ipv4":
                ip = addr.get("addr")
            elif t == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")

        if not ip:
            continue
        key = HostKey(mac=mac, ip=ip)

        if mac:
            yield MacFact(mac=mac, ip=ip, vendor=vendor, src="active.nmap")

        for hn in host_el.iterfind("hostnames/hostname"):
            name = hn.get("name")
            if name:
                yield HostnameFact(host_key=key, hostname=name, src="active.nmap")

        for port_el in host_el.iterfind("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            proto = port_el.get("protocol")
            portid = port_el.get("portid")
            if proto not in {"tcp", "udp"} or portid is None:
                continue
            svc_el = port_el.find("service")
            yield PortFact(
                host_key=key,
                proto=proto,  # type: ignore[arg-type]
                port=int(portid),
                state="open",
                service=svc_el.get("name") if svc_el is not None else None,
                version=_compose_version(svc_el),
            )

        for osmatch in host_el.iterfind("os/osmatch"):
            osclass = osmatch.find("osclass")
            yield OsFact(
                host_key=key,
                family=osclass.get("osfamily") if osclass is not None else None,
                detail=osmatch.get("name"),
            )
            t = osclass.get("type") if osclass is not None else None
            if t in {"router", "firewall", "switch", "broadband router", "WAP"}:
                yield DeviceTypeFact(host_key=key, device_type="router")


def _compose_version(svc_el) -> str | None:
    if svc_el is None:
        return None
    parts = [svc_el.get("product"), svc_el.get("version")]
    parts = [p for p in parts if p]
    return " ".join(parts) if parts else None


def _flags_for_mode(
    mode: ScanMode,
    *,
    default_host_timeout: str = "5m",
    deep_host_timeout: str = "30m",
) -> list[str]:
    if mode == ScanMode.DISCOVER:
        return ["-sn", "-PR", "-PE", "-PA80,443", "-T4"]
    if mode == ScanMode.DEFAULT:
        return [
            "-sS", "-O", "--top-ports", "100", "-T4",
            "--host-timeout", default_host_timeout, "--max-retries", "2",
        ]
    if mode == ScanMode.DEEP:
        return [
            "-sS", "-sV", "-O", "-p-", "-T3",
            "--host-timeout", deep_host_timeout, "--max-retries", "2",
        ]
    raise ValueError(f"unknown ScanMode: {mode!r}")


class NmapScanner:
    """Subprocess-backed active scanner. Implements ``ActiveScanner``."""

    name: ClassVar[str] = "active.nmap"

    def __init__(
        self,
        binary: str | None = None,
        *,
        default_host_timeout: str = "5m",
        deep_host_timeout: str = "30m",
    ) -> None:
        self._binary = binary or shutil.which("nmap") or "nmap"
        self._default_host_timeout = default_host_timeout
        self._deep_host_timeout = deep_host_timeout

    async def scan(
        self, target: IPv4Network, mode: ScanMode
    ) -> AsyncIterator[Fact]:
        flags = _flags_for_mode(
            mode,
            default_host_timeout=self._default_host_timeout,
            deep_host_timeout=self._deep_host_timeout,
        )
        args = [self._binary, "-oX", "-", *flags, str(target)]
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                f"nmap exited {proc.returncode}: {stderr.decode().strip()}"
            )
        for fact in parse_nmap_xml(stdout.decode()):
            yield fact
