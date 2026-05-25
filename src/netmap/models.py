"""Typed in-memory and DB models for net-map.

Three groups:
  * `HostKey` — canonical identifier (MAC primary, IP fallback)
  * `*Fact` — raw observations emitted by scanners before correlation
  * DB DTOs (added in Task 3) — typed mirrors of SQLite rows
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, NamedTuple

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


class _Dto(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Host(_Dto):
    id: int | None = None
    mac: str | None = None
    primary_ip: str
    hostname: str | None = None
    vendor: str | None = None
    os_family: str | None = None
    os_detail: str | None = None
    device_type: str | None = None
    trusted: bool = False
    first_seen: datetime
    last_seen: datetime
    notes: str | None = None


class Port(_Dto):
    host_id: int
    protocol: Literal["tcp", "udp"]
    number: int
    state: str
    service: str | None = None
    version: str | None = None
    first_seen: datetime
    last_seen: datetime


class Edge(_Dto):
    id: int | None = None
    src_host_id: int
    dst_host_id: int
    kind: str
    weight: int = 1
    last_seen: datetime


class Subnet(_Dto):
    id: int | None = None
    cidr: str
    label: str | None = None
    source: Literal["config", "discovered"]
    enabled: bool = True
    hop_distance: int = 0
    first_seen: datetime


class Scan(_Dto):
    id: int | None = None
    started_at: datetime
    ended_at: datetime | None = None
    source: str
    target: str | None = None
    mode: str | None = None
    status: Literal["running", "ok", "error", "skipped"]
    hosts_seen: int = 0
    notes: str | None = None


class HostSnapshot(_Dto):
    id: int | None = None
    scan_id: int
    host_id: int
    ip: str
    hostname: str | None = None
    os_detail: str | None = None
    device_type: str | None = None
    open_ports: list[dict[str, Any]] = []
    captured_at: datetime


class Event(_Dto):
    id: int | None = None
    ts: datetime
    scan_id: int | None = None
    host_id: int | None = None
    kind: str
    payload: dict[str, Any] | None = None
