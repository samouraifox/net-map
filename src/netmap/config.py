"""Configuration loader for net-map.

Reads ``~/.netmap/config.toml``. Creates the file with defaults on first run.
Mutating runtime fields via the web API is M3 work — for M1, edit the file
directly and restart.
"""
from __future__ import annotations

import os
import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from netmap.scanner.safety import DEFAULT_DENY_CIDRS

DEFAULT_CONFIG_PATH = Path(os.path.expanduser("~/.netmap/config.toml"))


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ServerCfg(_Section):
    bind: str = "127.0.0.1"
    port: int = 8765
    bearer_token: str = ""


class ScanCfg(_Section):
    interval_s: int = 60
    default_scan_interval_s: int = 600
    default_scan_host_timeout: str = "5m"
    deep_scan_host_timeout: str = "30m"
    passive: bool = True


class SafetyCfg(_Section):
    deny_cidrs: list[str] = Field(default_factory=lambda: list(DEFAULT_DENY_CIDRS))
    allow_public_scan: bool = False
    max_target_hosts: int = 65_536
    max_hop_distance: int = 1
    auto_approve_discovered: bool = False


class UiCfg(_Section):
    default_layout: str = "subnet-grouped"
    host_detail_layout: str = "accordion"


class RetentionCfg(_Section):
    snapshot_days: int = 30
    scan_days: int = 30
    events_keep_forever: bool = True


class PassiveCfg(_Section):
    buffer_size: int = 10_000
    filter: str = (
        "arp or (udp port 67 or 68) or (udp port 5353) "
        "or (ether proto 0x88cc) or (ether dst 01:00:0c:cc:cc:cc)"
    )


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: ServerCfg = Field(default_factory=ServerCfg)
    scan: ScanCfg = Field(default_factory=ScanCfg)
    safety: SafetyCfg = Field(default_factory=SafetyCfg)
    ui: UiCfg = Field(default_factory=UiCfg)
    retention: RetentionCfg = Field(default_factory=RetentionCfg)
    passive: PassiveCfg = Field(default_factory=PassiveCfg)


_DEFAULT_TEMPLATE = """\
[server]
bind = "127.0.0.1"
port = 8765
bearer_token = ""

[scan]
interval_s = 60
default_scan_interval_s = 600
default_scan_host_timeout = "5m"
deep_scan_host_timeout = "30m"
passive = true

[safety]
allow_public_scan = false
max_target_hosts = 65536
max_hop_distance = 1
auto_approve_discovered = false

[ui]
default_layout = "subnet-grouped"
host_detail_layout = "accordion"

[retention]
snapshot_days = 30
scan_days = 30
events_keep_forever = true

[passive]
buffer_size = 10000
"""


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> Config:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_DEFAULT_TEMPLATE)
        return Config()
    with open(path, "rb") as f:
        data = tomllib.load(f)
    try:
        return Config(**data)
    except Exception as exc:
        # Surface pydantic's "extra inputs" error as a friendly ValueError.
        raise ValueError(f"invalid {path}: {exc}") from exc
