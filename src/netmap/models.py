"""Typed in-memory and DB models for net-map.

Three groups:
  * `HostKey` — canonical identifier (MAC primary, IP fallback)
  * `*Fact` — raw observations emitted by scanners before correlation
  * DB DTOs (added in Task 3) — typed mirrors of SQLite rows
"""
from __future__ import annotations

from typing import Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field


class HostKey(NamedTuple):
    mac: str | None
    ip: str


class _Fact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class MacFact(_Fact):
    mac: str
    ip: str
    vendor: str | None = None
    src: str


class PortFact(_Fact):
    host_key: HostKey
    proto: Literal["tcp", "udp"]
    port: int = Field(ge=1, le=65535)
    state: str
    service: str | None = None
    version: str | None = None


class EdgeFact(_Fact):
    src: HostKey
    dst: HostKey
    kind: Literal["gateway", "arp", "broadcast", "observed"]


class OsFact(_Fact):
    host_key: HostKey
    family: str | None = None
    detail: str | None = None


class HostnameFact(_Fact):
    host_key: HostKey
    hostname: str
    src: str


class DeviceTypeFact(_Fact):
    host_key: HostKey
    device_type: Literal["router", "server", "endpoint", "iot", "unknown"]


Fact = MacFact | PortFact | EdgeFact | OsFact | HostnameFact | DeviceTypeFact
