"""nmap binary wrapper + XML parser.

The parser is a pure function over XML text — easy to unit-test against fixture
files. The subprocess wrapper is added in T16.
"""
from __future__ import annotations

from collections.abc import Iterable
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
