"""Response DTOs for the REST API. Reuses M1 DB DTOs where possible;
presentation-only shapes (HostSummary, HostDetail) live here.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from netmap.models import Edge, Event, Host, Port
from netmap.scanner.base import ScanMode


class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HostSummary(_Out):
    id: int
    mac: str | None = None
    primary_ip: str
    hostname: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    trusted: bool = False
    open_port_count: int
    last_seen: datetime


class HostIp(_Out):
    ip: str
    first_seen: datetime
    last_seen: datetime


class HostDetail(_Out):
    host: Host
    open_ports: list[Port]
    ip_history: list[HostIp]
    edges: list[Edge]
    recent_events: list[Event]


class ScanRequest(_Out):
    mode: ScanMode
    targets: list[str] | None = None
    confirm: bool = False


class ScanResponse(_Out):
    scan_id: int
    accepted_targets: list[str]
