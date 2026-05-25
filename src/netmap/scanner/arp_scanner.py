"""Active ARP scanner using scapy.

scapy's ``srp`` is blocking, so we offload it to a worker thread via
``asyncio.to_thread``. ARP is link-layer-only — only usable on the local subnet.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from ipaddress import IPv4Network
from typing import ClassVar

from scapy.layers.l2 import ARP, Ether  # type: ignore[import-untyped]
from scapy.sendrecv import srp  # type: ignore[import-untyped]

from netmap.models import Fact, MacFact
from netmap.scanner.base import ScanMode


class ArpScanner:
    name: ClassVar[str] = "active.arp"

    def __init__(self, iface: str | None = None, timeout: int = 2) -> None:
        self._iface = iface
        self._timeout = timeout

    async def scan(
        self, target: IPv4Network, mode: ScanMode
    ) -> AsyncIterator[Fact]:
        del mode  # ARP has no mode variants
        ans, _ = await asyncio.to_thread(self._srp_blocking, str(target))
        for _, rcv in ans:
            yield MacFact(mac=rcv.hwsrc, ip=rcv.psrc, src=self.name)

    def _srp_blocking(self, cidr: str):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        return srp(pkt, iface=self._iface, timeout=self._timeout, verbose=False)
