"""Active scanner Protocol and ScanMode enum.

Passive scanners use a different shape (thread + callback) defined in M3.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from enum import StrEnum
from ipaddress import IPv4Network
from typing import ClassVar, Protocol, runtime_checkable

from netmap.models import Fact


class ScanMode(StrEnum):
    DISCOVER = "discover"
    DEFAULT = "default"
    DEEP = "deep"


@runtime_checkable
class ActiveScanner(Protocol):
    name: ClassVar[str]

    def scan(self, target: IPv4Network, mode: ScanMode) -> AsyncIterator[Fact]:
        """Yield ``Fact`` objects for ``target``."""
        ...
