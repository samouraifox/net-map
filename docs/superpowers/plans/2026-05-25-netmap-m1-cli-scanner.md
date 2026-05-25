# net-map M1 — Foundation + CLI Scanner

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **The maintainer's preference for this project is that an implementation agent (Opus, high/xhigh effort) executes this plan — do not implement inline from a max-effort planning session.**

**Goal:** Ship `sudo netmap scan --target <CIDR> --mode {discover|default|deep}` — a working CLI that discovers hosts via nmap + scapy ARP, validates targets, correlates raw facts into typed records, and persists everything in SQLite with snapshot history and a change-event log.

**Architecture:** Single Python package under `src/`, managed by `uv`. SQLite via stdlib `sqlite3` (file at runtime, `:memory:` in tests). Pydantic 2 for typed models, Typer for the CLI, scapy for ARP, the `nmap` binary wrapped via `asyncio.create_subprocess_exec`. Correlation and safety logic are pure functions; scanner I/O hides behind a Protocol so unit tests pass mock scanners. TDD throughout: every behavior gets a failing test before any implementation.

**Tech stack:** Python ≥3.13, uv, Pydantic 2.x, Typer ≥0.16, scapy ≥2.6, anyio (test async helpers), pytest + pytest-asyncio + pytest-mock.

**Scope deferred:**
- **M2:** scan loop, FastAPI server, REST/SSE, web UI.
- **M3:** passive sniffer, gateway traversal, retention, export, runtime config mutation via API.

**Spec reference:** `docs/superpowers/specs/2026-05-25-netmap-design.md` is the source of truth. If anything below contradicts the spec, the spec wins — flag and ask.

---

## File structure (M1)

```
net-map/
├── pyproject.toml
├── README.md
├── .github/workflows/ci.yml
├── src/netmap/
│   ├── __init__.py                # version constant
│   ├── __main__.py                # python -m netmap → cli
│   ├── cli.py                     # Typer entry + commands
│   ├── config.py                  # Config dataclass + load_config + DEFAULT_DENY_CIDRS
│   ├── models.py                  # HostKey + Fact types + DB DTOs
│   ├── oui.py                     # lookup_vendor + bundled CSV reader
│   ├── data/oui.csv               # bundled IEEE OUI fixture (top 50 vendors for M1)
│   ├── storage.py                 # Storage class wrapping sqlite3
│   ├── correlation.py             # correlate(facts, db, scan_id) → list[Event]
│   └── scanner/
│       ├── __init__.py
│       ├── base.py                # ActiveScanner Protocol + ScanMode enum + ScanRun helper
│       ├── safety.py              # validate_target pure function + DENY_DEFAULTS
│       ├── nmap_scanner.py        # NmapScanner — subprocess + XML parsing
│       └── arp_scanner.py         # ArpScanner — scapy srp wrapper
└── tests/
    ├── __init__.py
    ├── conftest.py                # tmp_db fixture, sample_config, fake clock
    ├── fixtures/
    │   ├── oui-snippet.csv
    │   ├── nmap-discover-sample.xml
    │   ├── nmap-default-sample.xml
    │   └── nmap-empty.xml
    ├── unit/
    │   ├── __init__.py
    │   ├── test_models.py
    │   ├── test_oui.py
    │   ├── test_safety.py
    │   ├── test_config.py
    │   ├── test_storage.py
    │   ├── test_correlation.py
    │   ├── test_nmap_scanner.py
    │   └── test_arp_scanner.py
    └── integration/
        ├── __init__.py
        └── test_scan_smoke.py     # real nmap against 127.0.0.1/32 — skipped if nmap missing
```

Boundaries: `models.py` defines types only (no side effects). `safety.py`, `oui.py`, `correlation.py` are pure functions. `storage.py` owns all sqlite calls. `scanner/*` owns network/subprocess I/O. `cli.py` wires the others together. Tests target one module each.

---

## Task 1 — Project scaffold

**Files:**
- Create: `pyproject.toml`
- Create: `src/netmap/__init__.py`
- Create: `src/netmap/__main__.py`
- Create: `src/netmap/cli.py`
- Create: `tests/__init__.py`
- Create: `tests/unit/__init__.py`
- Create: `tests/integration/__init__.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[project]
name = "netmap"
version = "0.1.0"
description = "Continuous inventory + topology visualizer for local networks"
requires-python = ">=3.13"
authors = [{ name = "Aymen", email = "aymen09112004@gmail.com" }]
readme = "README.md"
license = { text = "MIT" }
dependencies = [
    "typer>=0.16.0",
    "pydantic>=2.9",
    "scapy>=2.6",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.3",
    "pytest-asyncio>=0.24",
    "pytest-mock>=3.14",
    "anyio>=4.6",
    "ruff>=0.6",
]

[project.scripts]
netmap = "netmap.cli:app"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/netmap"]

[tool.hatch.build.targets.wheel.force-include]
"src/netmap/data" = "netmap/data"

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra -q --strict-markers"
asyncio_mode = "auto"
markers = [
    "integration: tests that exercise external binaries / sockets (deselect with -m 'not integration')",
]

[tool.ruff]
line-length = 100
target-version = "py313"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM"]
```

- [ ] **Step 2: Write the empty package + CLI stub**

`src/netmap/__init__.py`:
```python
__version__ = "0.1.0"
```

`src/netmap/__main__.py`:
```python
from netmap.cli import app

if __name__ == "__main__":
    app()
```

`src/netmap/cli.py`:
```python
"""net-map CLI entry point.

Subcommands are registered in later tasks. This stub keeps the package importable
and gives us a `netmap version` smoke command.
"""
import typer

from netmap import __version__

app = typer.Typer(help="net-map — continuous inventory + topology visualizer", no_args_is_help=True)


@app.command()
def version() -> None:
    """Print the installed netmap version."""
    typer.echo(__version__)
```

Empty files: `tests/__init__.py`, `tests/unit/__init__.py`, `tests/integration/__init__.py`.

`tests/conftest.py`:
```python
"""Shared pytest fixtures. Concrete fixtures are added in later tasks."""
```

Create the data dir placeholder: `src/netmap/data/.gitkeep` (empty).

- [ ] **Step 3: Install with uv and verify the CLI runs**

Run:
```bash
uv sync --extra dev
uv run netmap version
```
Expected:
```
0.1.0
```

- [ ] **Step 4: Verify pytest finds zero tests cleanly**

Run: `uv run pytest`
Expected exit code: 5 (no tests collected) or 0 with `no tests ran`. Either is fine.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/netmap/ tests/
git commit -m "chore: project scaffold (uv, typer, pydantic, scapy)"
```

---

## Task 2 — `HostKey` and `Fact` types

**Files:**
- Create: `src/netmap/models.py`
- Create: `tests/unit/test_models.py`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_models.py`:
```python
import pytest
from pydantic import ValidationError

from netmap.models import (
    DeviceTypeFact,
    EdgeFact,
    HostKey,
    HostnameFact,
    MacFact,
    OsFact,
    PortFact,
)


class TestHostKey:
    def test_with_mac_and_ip(self) -> None:
        key = HostKey(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.1")
        assert key.mac == "aa:bb:cc:dd:ee:ff"
        assert key.ip == "192.168.1.1"

    def test_with_ip_only(self) -> None:
        key = HostKey(mac=None, ip="10.0.0.5")
        assert key.mac is None

    def test_is_hashable(self) -> None:
        key1 = HostKey(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.1")
        key2 = HostKey(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.1")
        assert {key1, key2} == {key1}


class TestFacts:
    def test_mac_fact(self) -> None:
        f = MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp")
        assert f.vendor is None
        assert f.src == "active.arp"

    def test_port_fact_requires_valid_proto(self) -> None:
        with pytest.raises(ValidationError):
            PortFact(
                host_key=HostKey(mac=None, ip="1.1.1.1"),
                proto="icmp",  # type: ignore[arg-type]
                port=22,
                state="open",
            )

    def test_port_fact_valid(self) -> None:
        f = PortFact(
            host_key=HostKey(mac=None, ip="1.1.1.1"),
            proto="tcp",
            port=22,
            state="open",
            service="ssh",
            version="OpenSSH 9.3",
        )
        assert f.service == "ssh"

    def test_edge_fact(self) -> None:
        f = EdgeFact(
            src=HostKey(mac="aa:bb:cc:dd:ee:01", ip="10.0.0.1"),
            dst=HostKey(mac="aa:bb:cc:dd:ee:02", ip="10.0.0.2"),
            kind="arp",
        )
        assert f.kind == "arp"

    def test_os_fact(self) -> None:
        f = OsFact(host_key=HostKey(mac=None, ip="1.1.1.1"), family="Linux", detail="Linux 5.x")
        assert f.family == "Linux"

    def test_hostname_fact(self) -> None:
        f = HostnameFact(
            host_key=HostKey(mac=None, ip="1.1.1.1"),
            hostname="nas.lan",
            src="active.nmap",
        )
        assert f.hostname == "nas.lan"

    def test_device_type_fact(self) -> None:
        f = DeviceTypeFact(host_key=HostKey(mac=None, ip="1.1.1.1"), device_type="router")
        assert f.device_type == "router"
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_models.py -v`
Expected: ImportError / ModuleNotFoundError on `netmap.models`.

- [ ] **Step 3: Implement `models.py`**

`src/netmap/models.py`:
```python
"""Typed in-memory and DB models for net-map.

Three groups:
  * `HostKey` — canonical identifier (MAC primary, IP fallback)
  * `*Fact` — raw observations emitted by scanners before correlation
  * DB DTOs (added in Task 3) — typed mirrors of SQLite rows
"""
from __future__ import annotations

from typing import Literal, NamedTuple

from pydantic import BaseModel, ConfigDict


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
    port: int
    state: str
    service: str | None = None
    version: str | None = None


class EdgeFact(_Fact):
    src: HostKey
    dst: HostKey
    kind: str  # "gateway" | "arp" | "broadcast" | "observed"


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
    device_type: str  # router | server | endpoint | iot | unknown


Fact = MacFact | PortFact | EdgeFact | OsFact | HostnameFact | DeviceTypeFact
```

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_models.py -v`
Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/models.py tests/unit/test_models.py
git commit -m "feat(models): HostKey and Fact types with pydantic validation"
```

---

## Task 3 — DB DTO models

**Files:**
- Modify: `src/netmap/models.py` (append)
- Modify: `tests/unit/test_models.py` (append)

- [ ] **Step 1: Append failing tests**

Append to `tests/unit/test_models.py`:
```python
from datetime import datetime, timezone

from netmap.models import (
    Edge,
    Event,
    Host,
    HostSnapshot,
    Port,
    Scan,
    Subnet,
)


def _now() -> datetime:
    return datetime(2026, 5, 25, 12, 0, tzinfo=timezone.utc)


class TestDtos:
    def test_host_round_trip(self) -> None:
        h = Host(
            id=1,
            mac="aa:bb:cc:dd:ee:ff",
            primary_ip="192.168.1.5",
            hostname="nas.lan",
            vendor="Synology",
            os_family="Linux",
            os_detail="Linux 4.x",
            device_type="server",
            trusted=False,
            first_seen=_now(),
            last_seen=_now(),
            notes=None,
        )
        assert h.id == 1
        assert h.trusted is False

    def test_port_dto(self) -> None:
        p = Port(
            host_id=1, protocol="tcp", number=22, state="open",
            service="ssh", version=None,
            first_seen=_now(), last_seen=_now(),
        )
        assert p.number == 22

    def test_edge_dto(self) -> None:
        e = Edge(id=1, src_host_id=1, dst_host_id=2, kind="arp", weight=3, last_seen=_now())
        assert e.weight == 3

    def test_subnet_dto(self) -> None:
        s = Subnet(
            id=1, cidr="192.168.1.0/24", label="home",
            source="config", enabled=True, hop_distance=0, first_seen=_now(),
        )
        assert s.enabled is True

    def test_scan_dto(self) -> None:
        s = Scan(
            id=1, started_at=_now(), ended_at=None,
            source="active.nmap", target="192.168.1.0/24",
            mode="discover", status="running", hosts_seen=0, notes=None,
        )
        assert s.status == "running"

    def test_host_snapshot(self) -> None:
        snap = HostSnapshot(
            id=1, scan_id=1, host_id=1, ip="192.168.1.5",
            hostname="nas.lan", os_detail=None, device_type="server",
            open_ports=[{"proto": "tcp", "port": 22, "svc": "ssh", "ver": None}],
            captured_at=_now(),
        )
        assert snap.open_ports[0]["port"] == 22

    def test_event_dto(self) -> None:
        e = Event(
            id=1, ts=_now(), scan_id=1, host_id=1,
            kind="port.opened",
            payload={"proto": "tcp", "port": 9000, "service": "http"},
        )
        assert e.kind == "port.opened"
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_models.py::TestDtos -v`
Expected: ImportError on the new symbols.

- [ ] **Step 3: Append DTOs to `models.py`**

Append:
```python
from datetime import datetime
from typing import Any


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
```

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_models.py -v`
Expected: 16 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/models.py tests/unit/test_models.py
git commit -m "feat(models): DB DTOs (Host, Port, Edge, Subnet, Scan, HostSnapshot, Event)"
```

---

## Task 4 — OUI lookup

**Files:**
- Create: `src/netmap/data/oui.csv`
- Create: `src/netmap/oui.py`
- Create: `tests/unit/test_oui.py`
- Create: `tests/fixtures/oui-snippet.csv`

- [ ] **Step 1: Create fixture data and tests**

`src/netmap/data/oui.csv` — bundled OUI seed (M1 ships 5 rows; the spec's `netmap update-oui` lands in M3):
```
prefix,vendor
3C5AB4,Synology Inc.
A45E60,Apple Inc.
F4F5E8,Espressif Inc.
B827EB,Raspberry Pi Foundation
001E58,WistronNeWeb Corporation
```

`tests/fixtures/oui-snippet.csv`:
```
prefix,vendor
AABBCC,Test Vendor Corp
DEADBE,Acme Industrial
```

`tests/unit/test_oui.py`:
```python
from pathlib import Path

import pytest

from netmap.oui import lookup_vendor, normalize_mac

FIXTURE = Path(__file__).parent.parent / "fixtures" / "oui-snippet.csv"


@pytest.fixture(autouse=True)
def _use_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the OUI loader at the test fixture for the duration of this module."""
    import netmap.oui as oui_mod
    monkeypatch.setattr(oui_mod, "_OUI_CSV_PATH", FIXTURE)
    oui_mod._reset_cache()


class TestNormalizeMac:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("AA:BB:CC:DD:EE:FF", "AABBCCDDEEFF"),
            ("aa-bb-cc-dd-ee-ff", "AABBCCDDEEFF"),
            ("aabb.ccdd.eeff", "AABBCCDDEEFF"),
            ("AABBCCDDEEFF", "AABBCCDDEEFF"),
        ],
    )
    def test_normalizes(self, raw: str, expected: str) -> None:
        assert normalize_mac(raw) == expected

    def test_rejects_too_short(self) -> None:
        with pytest.raises(ValueError):
            normalize_mac("AA:BB:CC")


class TestLookupVendor:
    def test_known_prefix(self) -> None:
        assert lookup_vendor("aa:bb:cc:11:22:33") == "Test Vendor Corp"

    def test_known_dotted(self) -> None:
        assert lookup_vendor("DEAD.BEEF.0000") == "Acme Industrial"

    def test_unknown_prefix(self) -> None:
        assert lookup_vendor("12:34:56:78:90:AB") is None

    def test_invalid_mac_returns_none(self) -> None:
        assert lookup_vendor("not-a-mac") is None
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_oui.py -v`
Expected: ImportError on `netmap.oui`.

- [ ] **Step 3: Implement `oui.py`**

`src/netmap/oui.py`:
```python
"""MAC OUI vendor lookup against the bundled IEEE CSV.

Format of the CSV: two columns, ``prefix`` (6 uppercase hex digits) and ``vendor``.
The full IEEE registration is refreshed via ``netmap update-oui`` (M3).
"""
from __future__ import annotations

import csv
import re
from importlib import resources
from pathlib import Path

_OUI_CSV_PATH: Path | None = None  # set lazily; tests can monkeypatch
_CACHE: dict[str, str] | None = None
_MAC_HEX_RE = re.compile(r"[0-9A-F]")


def _default_csv_path() -> Path:
    return Path(str(resources.files("netmap").joinpath("data/oui.csv")))


def _load() -> dict[str, str]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    path = _OUI_CSV_PATH or _default_csv_path()
    table: dict[str, str] = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            prefix = row["prefix"].strip().upper()
            vendor = row["vendor"].strip()
            if len(prefix) == 6 and vendor:
                table[prefix] = vendor
    _CACHE = table
    return table


def _reset_cache() -> None:
    """Test-only: drop the in-memory OUI cache."""
    global _CACHE
    _CACHE = None


def normalize_mac(raw: str) -> str:
    """Return ``raw`` as uppercase hex with no separators.

    Accepts ``aa:bb:cc:dd:ee:ff``, ``aa-bb-cc-dd-ee-ff``, ``aabb.ccdd.eeff``,
    or already-normalized ``AABBCCDDEEFF``. Raises ValueError for anything else.
    """
    upper = raw.upper()
    digits = "".join(ch for ch in upper if _MAC_HEX_RE.match(ch))
    if len(digits) != 12:
        raise ValueError(f"not a 48-bit MAC address: {raw!r}")
    return digits


def lookup_vendor(mac: str) -> str | None:
    """Return the vendor name for the OUI of ``mac``, or ``None`` if unknown."""
    try:
        norm = normalize_mac(mac)
    except ValueError:
        return None
    prefix = norm[:6]
    return _load().get(prefix)
```

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_oui.py -v`
Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/oui.py src/netmap/data/oui.csv tests/unit/test_oui.py tests/fixtures/oui-snippet.csv
git commit -m "feat(oui): MAC vendor lookup against bundled IEEE OUI CSV"
```

---

## Task 5 — `validate_target` safety

**Files:**
- Create: `src/netmap/scanner/__init__.py` (empty)
- Create: `src/netmap/scanner/safety.py`
- Create: `tests/unit/test_safety.py`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_safety.py`:
```python
from ipaddress import IPv4Network

import pytest

from netmap.scanner.safety import (
    DEFAULT_DENY_CIDRS,
    SafetyError,
    SafetyPolicy,
    validate_target,
)


@pytest.fixture
def policy() -> SafetyPolicy:
    return SafetyPolicy(
        deny_cidrs=DEFAULT_DENY_CIDRS,
        allow_public_scan=False,
        max_target_hosts=65_536,
        max_hop_distance=1,
    )


class TestValidateTarget:
    def test_rfc1918_24_ok(self, policy: SafetyPolicy) -> None:
        assert validate_target("192.168.1.0/24", policy) == IPv4Network("192.168.1.0/24")

    def test_loopback_rejected(self, policy: SafetyPolicy) -> None:
        with pytest.raises(SafetyError, match="deny_cidrs"):
            validate_target("127.0.0.0/8", policy)

    def test_link_local_rejected(self, policy: SafetyPolicy) -> None:
        with pytest.raises(SafetyError, match="deny_cidrs"):
            validate_target("169.254.0.0/16", policy)

    def test_multicast_rejected(self, policy: SafetyPolicy) -> None:
        with pytest.raises(SafetyError, match="deny_cidrs"):
            validate_target("224.0.0.0/4", policy)

    def test_public_rejected_without_confirm(self, policy: SafetyPolicy) -> None:
        with pytest.raises(SafetyError, match="public"):
            validate_target("8.8.8.0/24", policy)

    def test_public_allowed_with_confirm_and_setting(self, policy: SafetyPolicy) -> None:
        policy.allow_public_scan = True
        assert validate_target("8.8.8.0/24", policy, confirm=True) == IPv4Network("8.8.8.0/24")

    def test_public_rejected_with_confirm_but_setting_off(self, policy: SafetyPolicy) -> None:
        with pytest.raises(SafetyError, match="allow_public_scan"):
            validate_target("8.8.8.0/24", policy, confirm=True)

    def test_too_large_rejected(self, policy: SafetyPolicy) -> None:
        # /15 is 131,072 addresses; default cap is 65,536
        with pytest.raises(SafetyError, match="max_target_hosts"):
            validate_target("10.0.0.0/15", policy)

    def test_at_cap_allowed(self, policy: SafetyPolicy) -> None:
        # /16 == 65,536 addresses == exact cap
        assert validate_target("10.0.0.0/16", policy) == IPv4Network("10.0.0.0/16")

    def test_single_host(self, policy: SafetyPolicy) -> None:
        assert validate_target("127.0.0.1/32", policy, override_deny=True) == IPv4Network("127.0.0.1/32")

    def test_malformed_cidr_raises(self, policy: SafetyPolicy) -> None:
        with pytest.raises(SafetyError, match="parse"):
            validate_target("not-a-cidr", policy)

    def test_hop_distance_too_far(self, policy: SafetyPolicy) -> None:
        with pytest.raises(SafetyError, match="max_hop_distance"):
            validate_target("192.168.5.0/24", policy, hop_distance=3)

    def test_hop_distance_ok(self, policy: SafetyPolicy) -> None:
        assert validate_target("192.168.5.0/24", policy, hop_distance=1)
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_safety.py -v`
Expected: ImportError on `netmap.scanner.safety`.

- [ ] **Step 3: Implement `safety.py`**

`src/netmap/scanner/__init__.py`: (empty)

`src/netmap/scanner/safety.py`:
```python
"""Pure-function safety validation for scan targets.

Every scanner entry point (CLI, scan loop, API) routes through ``validate_target``.
No bypass paths: bypassing this is a bug.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import AddressValueError, IPv4Network, NetmaskValueError


class SafetyError(ValueError):
    """Raised when a scan target violates the configured safety policy."""


DEFAULT_DENY_CIDRS: tuple[str, ...] = (
    "0.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)


@dataclass
class SafetyPolicy:
    deny_cidrs: tuple[str, ...] = field(default_factory=lambda: DEFAULT_DENY_CIDRS)
    allow_public_scan: bool = False
    max_target_hosts: int = 65_536
    max_hop_distance: int = 1


def _parse(cidr: str) -> IPv4Network:
    try:
        return IPv4Network(cidr, strict=False)
    except (AddressValueError, NetmaskValueError, ValueError) as exc:
        raise SafetyError(f"could not parse target as IPv4 CIDR: {cidr!r}") from exc


def validate_target(
    target: str,
    policy: SafetyPolicy,
    *,
    confirm: bool = False,
    hop_distance: int = 0,
    override_deny: bool = False,
) -> IPv4Network:
    """Validate a single scan target against ``policy``.

    Returns the parsed ``IPv4Network`` on success; raises ``SafetyError`` otherwise.

    The ``override_deny`` flag is reserved for the smoke-test path that scans
    ``127.0.0.1/32`` deliberately. Production code never sets it.
    """
    net = _parse(target)

    if not override_deny:
        for deny in policy.deny_cidrs:
            if net.overlaps(IPv4Network(deny)):
                raise SafetyError(
                    f"{net} overlaps deny_cidrs entry {deny}"
                )

    if not net.is_private:
        if not policy.allow_public_scan:
            raise SafetyError(
                f"refusing public CIDR {net}: set allow_public_scan=true in config"
            )
        if not confirm:
            raise SafetyError(
                f"refusing public CIDR {net}: requires --i-understand confirmation"
            )

    if net.num_addresses > policy.max_target_hosts:
        raise SafetyError(
            f"{net} has {net.num_addresses} addresses; exceeds max_target_hosts={policy.max_target_hosts}"
        )

    if hop_distance > policy.max_hop_distance:
        raise SafetyError(
            f"hop_distance={hop_distance} exceeds max_hop_distance={policy.max_hop_distance}"
        )

    return net
```

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_safety.py -v`
Expected: 13 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/scanner/__init__.py src/netmap/scanner/safety.py tests/unit/test_safety.py
git commit -m "feat(safety): validate_target with deny_cidrs / public / size / hop rules"
```

---

## Task 6 — Config loader

**Files:**
- Create: `src/netmap/config.py`
- Create: `tests/unit/test_config.py`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_config.py`:
```python
from pathlib import Path

import pytest

from netmap.config import DEFAULT_CONFIG_PATH, Config, load_config


class TestConfigDefaults:
    def test_default_values(self) -> None:
        c = Config()
        assert c.scan.interval_s == 60
        assert c.scan.default_scan_interval_s == 600
        assert c.scan.passive is True
        assert c.safety.allow_public_scan is False
        assert c.safety.max_target_hosts == 65_536
        assert c.safety.max_hop_distance == 1
        assert c.server.bind == "127.0.0.1"
        assert c.server.port == 8765
        assert c.retention.snapshot_days == 30


class TestLoadConfig:
    def test_creates_default_file_when_missing(self, tmp_path: Path) -> None:
        path = tmp_path / "config.toml"
        cfg = load_config(path)
        assert path.exists()
        assert cfg.scan.interval_s == 60

    def test_returns_existing(self, tmp_path: Path) -> None:
        path = tmp_path / "config.toml"
        path.write_text(
            '[scan]\ninterval_s = 30\n'
            '[safety]\nmax_hop_distance = 3\n'
        )
        cfg = load_config(path)
        assert cfg.scan.interval_s == 30
        assert cfg.safety.max_hop_distance == 3
        # defaults preserved for unset keys
        assert cfg.scan.default_scan_interval_s == 600

    def test_unknown_keys_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "config.toml"
        path.write_text('[scan]\nbogus_key = 1\n')
        with pytest.raises(ValueError, match="bogus_key"):
            load_config(path)
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_config.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement `config.py`**

`src/netmap/config.py`:
```python
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
```

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_config.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/config.py tests/unit/test_config.py
git commit -m "feat(config): Config model + load_config (default file on first run)"
```

---

## Task 7 — Storage: schema bootstrap

**Files:**
- Create: `src/netmap/storage.py`
- Create: `tests/unit/test_storage.py`

- [ ] **Step 1: Write failing test**

`tests/unit/test_storage.py`:
```python
import pytest

from netmap.storage import Storage

EXPECTED_TABLES = {
    "host", "host_ip", "subnet", "port", "edge",
    "scan", "host_snapshot", "event",
}


@pytest.fixture
def db() -> Storage:
    return Storage(":memory:")


class TestSchema:
    def test_tables_exist(self, db: Storage) -> None:
        rows = db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        names = {r[0] for r in rows}
        assert EXPECTED_TABLES.issubset(names)

    def test_idempotent_init(self, db: Storage) -> None:
        # Re-running init must not blow up
        db._init_schema()
        rows = db._conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        assert len(rows) >= len(EXPECTED_TABLES)

    def test_mac_unique_partial_index(self, db: Storage) -> None:
        rows = db._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name='uq_host_mac'"
        ).fetchall()
        assert rows, "expected partial unique index uq_host_mac"
        assert "WHERE mac IS NOT NULL" in rows[0][0]
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_storage.py -v`
Expected: ImportError on `netmap.storage`.

- [ ] **Step 3: Implement `Storage` skeleton + schema**

`src/netmap/storage.py`:
```python
"""SQLite storage layer.

Wraps `sqlite3`. The schema is created on instantiation. All public methods are
synchronous; the async scan loop wraps them with ``asyncio.to_thread`` where
needed (called from `loop.py` in M2).
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS host (
  id          INTEGER PRIMARY KEY,
  mac         TEXT,
  primary_ip  TEXT NOT NULL,
  hostname    TEXT,
  vendor      TEXT,
  os_family   TEXT,
  os_detail   TEXT,
  device_type TEXT,
  trusted     INTEGER NOT NULL DEFAULT 0,
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  notes       TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_host_mac ON host(mac) WHERE mac IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_host_ip ON host(primary_ip);

CREATE TABLE IF NOT EXISTS host_ip (
  host_id    INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  ip         TEXT NOT NULL,
  subnet_id  INTEGER REFERENCES subnet(id),
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  PRIMARY KEY (host_id, ip)
);

CREATE TABLE IF NOT EXISTS subnet (
  id            INTEGER PRIMARY KEY,
  cidr          TEXT UNIQUE NOT NULL,
  label         TEXT,
  source        TEXT NOT NULL,
  enabled       INTEGER NOT NULL DEFAULT 1,
  hop_distance  INTEGER NOT NULL DEFAULT 0,
  first_seen    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS port (
  host_id    INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  protocol   TEXT NOT NULL,
  number     INTEGER NOT NULL,
  state      TEXT NOT NULL,
  service    TEXT,
  version    TEXT,
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  PRIMARY KEY (host_id, protocol, number)
);

CREATE TABLE IF NOT EXISTS edge (
  id          INTEGER PRIMARY KEY,
  src_host_id INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  dst_host_id INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  weight      INTEGER NOT NULL DEFAULT 1,
  last_seen   TEXT NOT NULL,
  UNIQUE (src_host_id, dst_host_id, kind)
);

CREATE TABLE IF NOT EXISTS scan (
  id         INTEGER PRIMARY KEY,
  started_at TEXT NOT NULL,
  ended_at   TEXT,
  source     TEXT NOT NULL,
  target     TEXT,
  mode       TEXT,
  status     TEXT NOT NULL,
  hosts_seen INTEGER NOT NULL DEFAULT 0,
  notes      TEXT
);

CREATE TABLE IF NOT EXISTS host_snapshot (
  id          INTEGER PRIMARY KEY,
  scan_id     INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  host_id     INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  ip          TEXT NOT NULL,
  hostname    TEXT,
  os_detail   TEXT,
  device_type TEXT,
  open_ports  TEXT,
  captured_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snap_scan ON host_snapshot(scan_id);
CREATE INDEX IF NOT EXISTS idx_snap_host ON host_snapshot(host_id, captured_at);

CREATE TABLE IF NOT EXISTS event (
  id      INTEGER PRIMARY KEY,
  ts      TEXT NOT NULL,
  scan_id INTEGER REFERENCES scan(id),
  host_id INTEGER REFERENCES host(id),
  kind    TEXT NOT NULL,
  payload TEXT
);
CREATE INDEX IF NOT EXISTS idx_event_ts ON event(ts);
"""


class Storage:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(path), isolation_level=None)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Run a block of statements inside a transaction."""
        self._conn.execute("BEGIN")
        try:
            yield self._conn
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise
```

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_storage.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/storage.py tests/unit/test_storage.py
git commit -m "feat(storage): SQLite schema + Storage class skeleton"
```

---

## Task 8 — Storage: host upsert + host_ip + subnet

**Files:**
- Modify: `src/netmap/storage.py`
- Modify: `tests/unit/test_storage.py`

- [ ] **Step 1: Append failing tests**

Append to `tests/unit/test_storage.py`:
```python
from datetime import datetime, timezone

from netmap.models import Host, Subnet

T0 = datetime(2026, 5, 25, 10, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 5, 25, 10, 1, tzinfo=timezone.utc)


def _host(ip: str, mac: str | None = "aa:bb:cc:dd:ee:01") -> Host:
    return Host(mac=mac, primary_ip=ip, first_seen=T0, last_seen=T0)


class TestSubnet:
    def test_insert_and_lookup(self, db: Storage) -> None:
        s = Subnet(cidr="192.168.1.0/24", source="config", first_seen=T0)
        row_id = db.insert_subnet(s)
        assert isinstance(row_id, int)
        got = db.get_subnet_by_cidr("192.168.1.0/24")
        assert got is not None
        assert got.id == row_id

    def test_idempotent_insert(self, db: Storage) -> None:
        s = Subnet(cidr="10.0.0.0/24", source="config", first_seen=T0)
        first = db.insert_subnet(s)
        second = db.insert_subnet(s)
        assert first == second


class TestHostUpsert:
    def test_insert_new_host(self, db: Storage) -> None:
        h = db.upsert_host(_host("192.168.1.5"))
        assert h.id is not None
        assert h.primary_ip == "192.168.1.5"

    def test_upsert_existing_by_mac_updates_last_seen(self, db: Storage) -> None:
        first = db.upsert_host(_host("192.168.1.5"))
        updated = db.upsert_host(_host("192.168.1.5").model_copy(update={"last_seen": T1}))
        assert updated.id == first.id
        assert updated.last_seen == T1

    def test_upsert_by_ip_when_no_mac(self, db: Storage) -> None:
        h = db.upsert_host(_host("10.0.0.7", mac=None))
        assert h.id is not None

    def test_ip_change_for_known_mac(self, db: Storage) -> None:
        first = db.upsert_host(_host("192.168.1.5"))
        # same MAC, new IP
        moved = db.upsert_host(_host("192.168.1.99").model_copy(update={"last_seen": T1}))
        assert moved.id == first.id
        assert moved.primary_ip == "192.168.1.99"
        ips = db.list_host_ips(first.id)  # type: ignore[arg-type]
        assert {row["ip"] for row in ips} == {"192.168.1.5", "192.168.1.99"}

    def test_mac_discovery_merges_records(self, db: Storage) -> None:
        # Earlier scan saw IP only (across-router, no MAC)
        ip_only = db.upsert_host(_host("192.168.1.5", mac=None))
        # Later scan from the actual subnet learns the MAC
        with_mac = db.upsert_host(_host("192.168.1.5", mac="aa:bb:cc:dd:ee:01")
                                  .model_copy(update={"last_seen": T1}))
        assert with_mac.id == ip_only.id
        assert with_mac.mac == "aa:bb:cc:dd:ee:01"
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_storage.py -v`
Expected: AttributeError — methods not defined.

- [ ] **Step 3: Implement subnet + host upsert**

Append to `src/netmap/storage.py`:
```python
from netmap.models import Host, Subnet


def _iso(dt: datetime) -> str:
    return dt.isoformat()


class Storage(Storage):  # type: ignore[no-redef]  # extend in same module
    # ---------- subnet ----------
    def insert_subnet(self, s: Subnet) -> int:
        cur = self._conn.execute(
            "INSERT INTO subnet(cidr, label, source, enabled, hop_distance, first_seen) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(cidr) DO UPDATE SET label=excluded.label",
            (s.cidr, s.label, s.source, int(s.enabled), s.hop_distance, _iso(s.first_seen)),
        )
        row = self._conn.execute("SELECT id FROM subnet WHERE cidr=?", (s.cidr,)).fetchone()
        return int(row[0])

    def get_subnet_by_cidr(self, cidr: str) -> Subnet | None:
        row = self._conn.execute(
            "SELECT id, cidr, label, source, enabled, hop_distance, first_seen "
            "FROM subnet WHERE cidr=?",
            (cidr,),
        ).fetchone()
        if not row:
            return None
        return Subnet(
            id=row[0], cidr=row[1], label=row[2], source=row[3],
            enabled=bool(row[4]), hop_distance=row[5],
            first_seen=datetime.fromisoformat(row[6]),
        )

    # ---------- host ----------
    def _find_host_by_mac(self, mac: str) -> Host | None:
        row = self._conn.execute(self._SELECT_HOST + " WHERE mac=?", (mac,)).fetchone()
        return self._row_to_host(row) if row else None

    def _find_host_by_ip(self, ip: str) -> Host | None:
        row = self._conn.execute(self._SELECT_HOST + " WHERE mac IS NULL AND primary_ip=?", (ip,)).fetchone()
        return self._row_to_host(row) if row else None

    _SELECT_HOST = (
        "SELECT id, mac, primary_ip, hostname, vendor, os_family, os_detail, "
        "device_type, trusted, first_seen, last_seen, notes FROM host"
    )

    @staticmethod
    def _row_to_host(row: tuple) -> Host:
        return Host(
            id=row[0], mac=row[1], primary_ip=row[2], hostname=row[3], vendor=row[4],
            os_family=row[5], os_detail=row[6], device_type=row[7], trusted=bool(row[8]),
            first_seen=datetime.fromisoformat(row[9]),
            last_seen=datetime.fromisoformat(row[10]), notes=row[11],
        )

    def upsert_host(self, h: Host) -> Host:
        """Upsert a host record using MAC-primary / IP-fallback identity.

        If a MAC-less host with the same primary_ip already exists and ``h`` carries
        a MAC, the two records are merged (the IP-only record is updated in place
        with the new MAC).
        """
        with self.tx() as conn:
            existing: Host | None = None
            if h.mac:
                existing = self._find_host_by_mac(h.mac)
                if existing is None:
                    # IP-only record waiting to be claimed by a MAC observation
                    existing = self._find_host_by_ip(h.primary_ip)

            if existing is None:
                cur = conn.execute(
                    "INSERT INTO host(mac, primary_ip, hostname, vendor, os_family, os_detail, "
                    "device_type, trusted, first_seen, last_seen, notes) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        h.mac, h.primary_ip, h.hostname, h.vendor, h.os_family, h.os_detail,
                        h.device_type, int(h.trusted), _iso(h.first_seen), _iso(h.last_seen), h.notes,
                    ),
                )
                host_id = cur.lastrowid
                self._upsert_host_ip(conn, host_id, h.primary_ip, h.first_seen, h.last_seen)
                return h.model_copy(update={"id": host_id})

            # update path
            new_mac = h.mac or existing.mac
            new_ip = h.primary_ip
            conn.execute(
                "UPDATE host SET mac=?, primary_ip=?, "
                "hostname=COALESCE(?, hostname), vendor=COALESCE(?, vendor), "
                "os_family=COALESCE(?, os_family), os_detail=COALESCE(?, os_detail), "
                "device_type=COALESCE(?, device_type), last_seen=? WHERE id=?",
                (new_mac, new_ip, h.hostname, h.vendor, h.os_family, h.os_detail,
                 h.device_type, _iso(h.last_seen), existing.id),
            )
            self._upsert_host_ip(conn, existing.id, new_ip, h.first_seen, h.last_seen)
            return self._find_host_by_mac(new_mac) if new_mac else self._find_host_by_ip(new_ip)  # type: ignore[return-value]

    def _upsert_host_ip(self, conn, host_id: int, ip: str, first_seen, last_seen) -> None:
        conn.execute(
            "INSERT INTO host_ip(host_id, ip, first_seen, last_seen) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(host_id, ip) DO UPDATE SET last_seen=excluded.last_seen",
            (host_id, ip, _iso(first_seen), _iso(last_seen)),
        )

    def list_host_ips(self, host_id: int) -> list[dict]:
        rows = self._conn.execute(
            "SELECT ip, first_seen, last_seen FROM host_ip WHERE host_id=? ORDER BY first_seen",
            (host_id,),
        ).fetchall()
        return [{"ip": r[0], "first_seen": r[1], "last_seen": r[2]} for r in rows]
```

> Note: the `class Storage(Storage)` pattern is just to keep the diff localized in this plan. When implementing, **merge the methods into the single `Storage` class** defined in Task 7. The end state is one class with all these methods.

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_storage.py -v`
Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/storage.py tests/unit/test_storage.py
git commit -m "feat(storage): host upsert with MAC/IP identity rule + host_ip history"
```

---

## Task 9 — Storage: ports + edges

**Files:**
- Modify: `src/netmap/storage.py`
- Modify: `tests/unit/test_storage.py`

- [ ] **Step 1: Append failing tests**

```python
from netmap.models import Edge, Port


class TestPort:
    def test_upsert_new_port(self, db: Storage) -> None:
        host = db.upsert_host(_host("192.168.1.5"))
        p = Port(host_id=host.id, protocol="tcp", number=22, state="open",
                 service="ssh", version=None, first_seen=T0, last_seen=T0)
        db.upsert_port(p)
        ports = db.list_ports(host.id)
        assert len(ports) == 1
        assert ports[0].number == 22

    def test_upsert_existing_updates_last_seen(self, db: Storage) -> None:
        host = db.upsert_host(_host("192.168.1.5"))
        p = Port(host_id=host.id, protocol="tcp", number=22, state="open",
                 service="ssh", version=None, first_seen=T0, last_seen=T0)
        db.upsert_port(p)
        db.upsert_port(p.model_copy(update={"last_seen": T1}))
        ports = db.list_ports(host.id)
        assert len(ports) == 1
        assert ports[0].last_seen == T1

    def test_close_port(self, db: Storage) -> None:
        host = db.upsert_host(_host("192.168.1.5"))
        p = Port(host_id=host.id, protocol="tcp", number=22, state="open",
                 service="ssh", version=None, first_seen=T0, last_seen=T0)
        db.upsert_port(p)
        db.close_port(host.id, "tcp", 22)
        assert db.list_ports(host.id, only_open=True) == []


class TestEdge:
    def test_upsert_edge_creates(self, db: Storage) -> None:
        a = db.upsert_host(_host("10.0.0.1", mac="aa:bb:cc:dd:ee:01"))
        b = db.upsert_host(_host("10.0.0.2", mac="aa:bb:cc:dd:ee:02"))
        e = Edge(src_host_id=a.id, dst_host_id=b.id, kind="arp", weight=1, last_seen=T0)
        db.upsert_edge(e)
        edges = db.list_edges()
        assert len(edges) == 1

    def test_upsert_edge_increments_weight(self, db: Storage) -> None:
        a = db.upsert_host(_host("10.0.0.1", mac="aa:bb:cc:dd:ee:01"))
        b = db.upsert_host(_host("10.0.0.2", mac="aa:bb:cc:dd:ee:02"))
        e = Edge(src_host_id=a.id, dst_host_id=b.id, kind="arp", weight=1, last_seen=T0)
        db.upsert_edge(e)
        db.upsert_edge(e.model_copy(update={"last_seen": T1}))
        edges = db.list_edges()
        assert edges[0].weight == 2
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_storage.py -v`
Expected: AttributeError on `upsert_port`, `upsert_edge`, etc.

- [ ] **Step 3: Implement port + edge methods**

Append to `Storage` in `src/netmap/storage.py`:

```python
    # ---------- port ----------
    def upsert_port(self, p: Port) -> None:
        self._conn.execute(
            "INSERT INTO port(host_id, protocol, number, state, service, version, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(host_id, protocol, number) DO UPDATE SET "
            "state=excluded.state, service=COALESCE(excluded.service, service), "
            "version=COALESCE(excluded.version, version), last_seen=excluded.last_seen",
            (p.host_id, p.protocol, p.number, p.state, p.service, p.version,
             _iso(p.first_seen), _iso(p.last_seen)),
        )

    def close_port(self, host_id: int, protocol: str, number: int) -> None:
        self._conn.execute(
            "UPDATE port SET state='closed' WHERE host_id=? AND protocol=? AND number=?",
            (host_id, protocol, number),
        )

    def list_ports(self, host_id: int, *, only_open: bool = False) -> list[Port]:
        sql = (
            "SELECT host_id, protocol, number, state, service, version, first_seen, last_seen "
            "FROM port WHERE host_id=?"
        )
        if only_open:
            sql += " AND state='open'"
        rows = self._conn.execute(sql, (host_id,)).fetchall()
        return [
            Port(
                host_id=r[0], protocol=r[1], number=r[2], state=r[3],
                service=r[4], version=r[5],
                first_seen=datetime.fromisoformat(r[6]),
                last_seen=datetime.fromisoformat(r[7]),
            )
            for r in rows
        ]

    # ---------- edge ----------
    def upsert_edge(self, e: Edge) -> None:
        self._conn.execute(
            "INSERT INTO edge(src_host_id, dst_host_id, kind, weight, last_seen) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(src_host_id, dst_host_id, kind) DO UPDATE SET "
            "weight=weight+1, last_seen=excluded.last_seen",
            (e.src_host_id, e.dst_host_id, e.kind, e.weight, _iso(e.last_seen)),
        )

    def list_edges(self) -> list[Edge]:
        rows = self._conn.execute(
            "SELECT id, src_host_id, dst_host_id, kind, weight, last_seen FROM edge"
        ).fetchall()
        return [
            Edge(id=r[0], src_host_id=r[1], dst_host_id=r[2], kind=r[3], weight=r[4],
                 last_seen=datetime.fromisoformat(r[5]))
            for r in rows
        ]
```

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_storage.py -v`
Expected: 13 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/storage.py tests/unit/test_storage.py
git commit -m "feat(storage): port + edge upserts"
```

---

## Task 10 — Storage: scans, snapshots, events

**Files:**
- Modify: `src/netmap/storage.py`
- Modify: `tests/unit/test_storage.py`

- [ ] **Step 1: Append failing tests**

```python
from netmap.models import Event, HostSnapshot, Scan


class TestScan:
    def test_start_then_finish_scan(self, db: Storage) -> None:
        sid = db.start_scan(Scan(started_at=T0, source="active.nmap",
                                  target="192.168.1.0/24", mode="discover",
                                  status="running"))
        db.finish_scan(sid, ended_at=T1, status="ok", hosts_seen=12)
        s = db.get_scan(sid)
        assert s.status == "ok"
        assert s.hosts_seen == 12


class TestSnapshot:
    def test_insert_snapshot_serializes_open_ports(self, db: Storage) -> None:
        host = db.upsert_host(_host("192.168.1.5"))
        sid = db.start_scan(Scan(started_at=T0, source="active.nmap", status="running"))
        snap = HostSnapshot(scan_id=sid, host_id=host.id, ip="192.168.1.5",
                            open_ports=[{"proto": "tcp", "port": 22}],
                            captured_at=T0)
        db.insert_snapshot(snap)
        latest = db.latest_snapshot(host.id)
        assert latest is not None
        assert latest.open_ports == [{"proto": "tcp", "port": 22}]


class TestEvent:
    def test_insert_and_list(self, db: Storage) -> None:
        sid = db.start_scan(Scan(started_at=T0, source="active.nmap", status="running"))
        host = db.upsert_host(_host("192.168.1.5"))
        evt = Event(ts=T0, scan_id=sid, host_id=host.id, kind="host.new",
                    payload={"ip": "192.168.1.5"})
        db.insert_event(evt)
        events = db.list_events()
        assert len(events) == 1
        assert events[0].kind == "host.new"
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_storage.py -v`
Expected: AttributeError on the new methods.

- [ ] **Step 3: Implement scan / snapshot / event methods**

Append:

```python
    # ---------- scan ----------
    def start_scan(self, s: Scan) -> int:
        cur = self._conn.execute(
            "INSERT INTO scan(started_at, source, target, mode, status, hosts_seen, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (_iso(s.started_at), s.source, s.target, s.mode, s.status, s.hosts_seen, s.notes),
        )
        return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, *, ended_at: datetime, status: str, hosts_seen: int) -> None:
        self._conn.execute(
            "UPDATE scan SET ended_at=?, status=?, hosts_seen=? WHERE id=?",
            (_iso(ended_at), status, hosts_seen, scan_id),
        )

    def get_scan(self, scan_id: int) -> Scan:
        row = self._conn.execute(
            "SELECT id, started_at, ended_at, source, target, mode, status, hosts_seen, notes "
            "FROM scan WHERE id=?",
            (scan_id,),
        ).fetchone()
        return Scan(
            id=row[0],
            started_at=datetime.fromisoformat(row[1]),
            ended_at=datetime.fromisoformat(row[2]) if row[2] else None,
            source=row[3], target=row[4], mode=row[5], status=row[6],
            hosts_seen=row[7], notes=row[8],
        )

    # ---------- host_snapshot ----------
    def insert_snapshot(self, snap: HostSnapshot) -> None:
        self._conn.execute(
            "INSERT INTO host_snapshot(scan_id, host_id, ip, hostname, os_detail, "
            "device_type, open_ports, captured_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (snap.scan_id, snap.host_id, snap.ip, snap.hostname, snap.os_detail,
             snap.device_type, json.dumps(snap.open_ports), _iso(snap.captured_at)),
        )

    def latest_snapshot(self, host_id: int) -> HostSnapshot | None:
        row = self._conn.execute(
            "SELECT id, scan_id, host_id, ip, hostname, os_detail, device_type, open_ports, captured_at "
            "FROM host_snapshot WHERE host_id=? ORDER BY captured_at DESC LIMIT 1",
            (host_id,),
        ).fetchone()
        if not row:
            return None
        return HostSnapshot(
            id=row[0], scan_id=row[1], host_id=row[2], ip=row[3], hostname=row[4],
            os_detail=row[5], device_type=row[6],
            open_ports=json.loads(row[7]) if row[7] else [],
            captured_at=datetime.fromisoformat(row[8]),
        )

    # ---------- event ----------
    def insert_event(self, e: Event) -> None:
        self._conn.execute(
            "INSERT INTO event(ts, scan_id, host_id, kind, payload) VALUES (?, ?, ?, ?, ?)",
            (_iso(e.ts), e.scan_id, e.host_id, e.kind,
             json.dumps(e.payload) if e.payload else None),
        )

    def list_events(self, *, since: datetime | None = None,
                    host_id: int | None = None, limit: int = 500) -> list[Event]:
        sql = "SELECT id, ts, scan_id, host_id, kind, payload FROM event WHERE 1=1"
        params: list = []
        if since:
            sql += " AND ts >= ?"
            params.append(_iso(since))
        if host_id:
            sql += " AND host_id = ?"
            params.append(host_id)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [
            Event(id=r[0], ts=datetime.fromisoformat(r[1]), scan_id=r[2], host_id=r[3],
                  kind=r[4], payload=json.loads(r[5]) if r[5] else None)
            for r in rows
        ]
```

Add `import json` at the top of `storage.py` if not already present.

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_storage.py -v`
Expected: 16 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/storage.py tests/unit/test_storage.py
git commit -m "feat(storage): scan / snapshot / event ops"
```

---

## Task 11 — Correlation: new host emits `host.new`

**Files:**
- Create: `src/netmap/correlation.py`
- Create: `tests/unit/test_correlation.py`

- [ ] **Step 1: Write failing test**

`tests/unit/test_correlation.py`:
```python
from datetime import datetime, timezone

import pytest

from netmap.correlation import correlate
from netmap.models import HostKey, MacFact, Scan
from netmap.storage import Storage

T0 = datetime(2026, 5, 25, 10, 0, tzinfo=timezone.utc)


@pytest.fixture
def db() -> Storage:
    return Storage(":memory:")


@pytest.fixture
def scan_id(db: Storage) -> int:
    return db.start_scan(Scan(started_at=T0, source="active.nmap", status="running"))


class TestNewHost:
    def test_emits_host_new(self, db: Storage, scan_id: int) -> None:
        facts = [MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp")]
        events = correlate(facts, db, scan_id, now=T0)
        kinds = [e.kind for e in events]
        assert "host.new" in kinds

    def test_persists_host_row(self, db: Storage, scan_id: int) -> None:
        correlate(
            [MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp")],
            db, scan_id, now=T0,
        )
        row = db._conn.execute("SELECT mac, primary_ip FROM host").fetchone()
        assert row == ("aa:bb:cc:dd:ee:ff", "192.168.1.5")

    def test_known_host_does_not_emit_new(self, db: Storage, scan_id: int) -> None:
        f = MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp")
        correlate([f], db, scan_id, now=T0)
        sid2 = db.start_scan(Scan(started_at=T0, source="active.nmap", status="running"))
        events = correlate([f], db, sid2, now=T0)
        assert "host.new" not in [e.kind for e in events]

    def test_vendor_filled_from_oui(self, db: Storage, scan_id: int,
                                    monkeypatch: pytest.MonkeyPatch) -> None:
        import netmap.correlation as corr
        monkeypatch.setattr(corr, "lookup_vendor", lambda mac: "Synology Inc.")
        correlate([MacFact(mac="3c:5a:b4:00:00:01", ip="192.168.1.5", src="active.arp")],
                  db, scan_id, now=T0)
        row = db._conn.execute("SELECT vendor FROM host").fetchone()
        assert row[0] == "Synology Inc."
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_correlation.py -v`
Expected: ImportError on `netmap.correlation`.

- [ ] **Step 3: Implement `correlate` (minimal — host upsert + host.new event)**

`src/netmap/correlation.py`:
```python
"""Pure-function correlation: ``facts → host records + change events``.

No network I/O. No subprocess calls. Inputs are scanner-produced ``Fact`` objects
plus a ``Storage`` handle; outputs are DB mutations and a list of ``Event``s.
This makes the entire correlation surface unit-testable with hand-built fact
lists — see ``tests/unit/test_correlation.py``.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from netmap.models import (
    DeviceTypeFact,
    EdgeFact,
    Event,
    Fact,
    Host,
    HostKey,
    HostnameFact,
    MacFact,
    OsFact,
    PortFact,
)
from netmap.oui import lookup_vendor
from netmap.storage import Storage


def correlate(
    facts: Iterable[Fact],
    db: Storage,
    scan_id: int,
    *,
    now: datetime | None = None,
) -> list[Event]:
    now = now or datetime.now(tz=timezone.utc)
    events: list[Event] = []

    # Group facts by HostKey for batched processing.
    by_key: dict[HostKey, list[Fact]] = {}
    for f in facts:
        key = _key_for(f)
        if key is None:
            continue
        by_key.setdefault(key, []).append(f)

    for key, host_facts in by_key.items():
        existing_id = _find_existing_host_id(db, key)
        host_dto = _build_host_dto(key, host_facts, now)
        updated = db.upsert_host(host_dto)

        if existing_id is None:
            events.append(Event(
                ts=now, scan_id=scan_id, host_id=updated.id, kind="host.new",
                payload={"ip": updated.primary_ip, "mac": updated.mac},
            ))

    # Persist events.
    for ev in events:
        db.insert_event(ev)

    return events


def _key_for(f: Fact) -> HostKey | None:
    if isinstance(f, MacFact):
        return HostKey(mac=f.mac, ip=f.ip)
    if isinstance(f, (PortFact, OsFact, HostnameFact, DeviceTypeFact)):
        return f.host_key
    return None  # EdgeFact handled in a future task


def _find_existing_host_id(db: Storage, key: HostKey) -> int | None:
    if key.mac:
        row = db._conn.execute("SELECT id FROM host WHERE mac=?", (key.mac,)).fetchone()
        if row:
            return int(row[0])
    row = db._conn.execute(
        "SELECT id FROM host WHERE mac IS NULL AND primary_ip=?", (key.ip,)
    ).fetchone()
    return int(row[0]) if row else None


def _build_host_dto(key: HostKey, facts: list[Fact], now: datetime) -> Host:
    hostname: str | None = None
    os_family: str | None = None
    os_detail: str | None = None
    device_type: str | None = None
    for f in facts:
        if isinstance(f, HostnameFact):
            hostname = f.hostname
        elif isinstance(f, OsFact):
            os_family = f.family or os_family
            os_detail = f.detail or os_detail
        elif isinstance(f, DeviceTypeFact):
            device_type = f.device_type

    vendor = lookup_vendor(key.mac) if key.mac else None

    return Host(
        mac=key.mac,
        primary_ip=key.ip,
        hostname=hostname,
        vendor=vendor,
        os_family=os_family,
        os_detail=os_detail,
        device_type=device_type,
        first_seen=now,
        last_seen=now,
    )
```

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_correlation.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/correlation.py tests/unit/test_correlation.py
git commit -m "feat(correlation): host upsert + host.new event emission"
```

---

## Task 12 — Correlation: port events

**Files:**
- Modify: `src/netmap/correlation.py`
- Modify: `tests/unit/test_correlation.py`

- [ ] **Step 1: Append failing tests**

```python
from netmap.models import PortFact


class TestPortEvents:
    def test_port_opened(self, db: Storage, scan_id: int) -> None:
        facts = [
            MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp"),
            PortFact(host_key=HostKey(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5"),
                     proto="tcp", port=22, state="open", service="ssh"),
        ]
        events = correlate(facts, db, scan_id, now=T0)
        kinds = [e.kind for e in events]
        assert "port.opened" in kinds

    def test_port_unchanged_no_event(self, db: Storage, scan_id: int) -> None:
        facts = [
            MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp"),
            PortFact(host_key=HostKey(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5"),
                     proto="tcp", port=22, state="open", service="ssh"),
        ]
        correlate(facts, db, scan_id, now=T0)
        # second scan, same ports
        sid2 = db.start_scan(Scan(started_at=T0, source="active.nmap", status="running"))
        events = correlate(facts, db, sid2, now=T0)
        assert "port.opened" not in [e.kind for e in events]

    def test_port_closed(self, db: Storage, scan_id: int) -> None:
        # First scan: port open
        facts1 = [
            MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp"),
            PortFact(host_key=HostKey(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5"),
                     proto="tcp", port=22, state="open", service="ssh"),
        ]
        correlate(facts1, db, scan_id, now=T0)
        # Second scan: same host but no port observed → port should close
        sid2 = db.start_scan(Scan(started_at=T0, source="active.nmap",
                                   target="192.168.1.0/24", mode="default",
                                   status="running"))
        facts2 = [MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp")]
        events = correlate(facts2, db, sid2, now=T0, observed_subnets=["192.168.1.0/24"])
        kinds = [e.kind for e in events]
        assert "port.closed" in kinds
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_correlation.py -v`
Expected: failures on the new tests.

- [ ] **Step 3: Implement port handling + close-detection**

Modify `correlate` to accept `observed_subnets` and extend the per-host loop:

```python
def correlate(
    facts: Iterable[Fact],
    db: Storage,
    scan_id: int,
    *,
    now: datetime | None = None,
    observed_subnets: list[str] | None = None,
) -> list[Event]:
    now = now or datetime.now(tz=timezone.utc)
    events: list[Event] = []
    observed_subnets = observed_subnets or []

    by_key: dict[HostKey, list[Fact]] = {}
    for f in facts:
        key = _key_for(f)
        if key is None:
            continue
        by_key.setdefault(key, []).append(f)

    for key, host_facts in by_key.items():
        existing_id = _find_existing_host_id(db, key)
        host_dto = _build_host_dto(key, host_facts, now)
        updated = db.upsert_host(host_dto)

        if existing_id is None:
            events.append(Event(
                ts=now, scan_id=scan_id, host_id=updated.id, kind="host.new",
                payload={"ip": updated.primary_ip, "mac": updated.mac},
            ))

        events.extend(_apply_ports(db, updated.id, host_facts, scan_id, now, observed_subnets, updated))

    for ev in events:
        db.insert_event(ev)
    return events


def _apply_ports(
    db: Storage,
    host_id: int,
    facts: list[Fact],
    scan_id: int,
    now: datetime,
    observed_subnets: list[str],
    host: Host,
) -> list[Event]:
    from netmap.models import Port
    events: list[Event] = []
    seen: set[tuple[str, int]] = set()
    for f in facts:
        if not isinstance(f, PortFact):
            continue
        seen.add((f.proto, f.port))
        existing = {
            (p.protocol, p.number) for p in db.list_ports(host_id, only_open=True)
        }
        db.upsert_port(Port(
            host_id=host_id, protocol=f.proto, number=f.port, state=f.state,
            service=f.service, version=f.version, first_seen=now, last_seen=now,
        ))
        if (f.proto, f.port) not in existing and f.state == "open":
            events.append(Event(
                ts=now, scan_id=scan_id, host_id=host_id, kind="port.opened",
                payload={"proto": f.proto, "port": f.port, "service": f.service, "version": f.version},
            ))

    # Closure detection: only if the host's subnet was actually observed AND the
    # scan contained port facts for this host (so a "discover" scan can't close ports).
    has_port_facts_for_host = any(isinstance(f, PortFact) for f in facts)
    if has_port_facts_for_host and _host_in_observed(host, observed_subnets):
        for p in db.list_ports(host_id, only_open=True):
            if (p.protocol, p.number) not in seen:
                db.close_port(host_id, p.protocol, p.number)
                events.append(Event(
                    ts=now, scan_id=scan_id, host_id=host_id, kind="port.closed",
                    payload={"proto": p.protocol, "port": p.number},
                ))
    return events


def _host_in_observed(host: Host, observed_subnets: list[str]) -> bool:
    if not observed_subnets:
        return False
    from ipaddress import IPv4Address, IPv4Network
    ip = IPv4Address(host.primary_ip)
    return any(ip in IPv4Network(c) for c in observed_subnets)
```

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_correlation.py -v`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/correlation.py tests/unit/test_correlation.py
git commit -m "feat(correlation): port.opened / port.closed events"
```

---

## Task 13 — Correlation: IP change, snapshot, scan finalization

**Files:**
- Modify: `src/netmap/correlation.py`
- Modify: `tests/unit/test_correlation.py`

- [ ] **Step 1: Append failing tests**

```python
from netmap.models import HostSnapshot


class TestIpChange:
    def test_dhcp_ip_change_emits_event(self, db: Storage, scan_id: int) -> None:
        correlate([MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp")],
                  db, scan_id, now=T0)
        sid2 = db.start_scan(Scan(started_at=T0, source="active.nmap", status="running"))
        events = correlate(
            [MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.99", src="active.arp")],
            db, sid2, now=T0,
        )
        assert "ip.changed" in [e.kind for e in events]


class TestSnapshot:
    def test_snapshot_written_per_host(self, db: Storage, scan_id: int) -> None:
        correlate([MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp")],
                  db, scan_id, now=T0)
        host_id = db._conn.execute("SELECT id FROM host").fetchone()[0]
        snap = db.latest_snapshot(host_id)
        assert snap is not None
        assert snap.ip == "192.168.1.5"
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_correlation.py -v`
Expected: failures.

- [ ] **Step 3: Add IP-change detection + per-host snapshot insert**

Replace the per-host loop in `correlate`:

```python
    for key, host_facts in by_key.items():
        existing = _find_existing_host(db, key)
        host_dto = _build_host_dto(key, host_facts, now)
        updated = db.upsert_host(host_dto)

        if existing is None:
            events.append(Event(
                ts=now, scan_id=scan_id, host_id=updated.id, kind="host.new",
                payload={"ip": updated.primary_ip, "mac": updated.mac},
            ))
        elif existing.primary_ip != updated.primary_ip:
            events.append(Event(
                ts=now, scan_id=scan_id, host_id=updated.id, kind="ip.changed",
                payload={"old": existing.primary_ip, "new": updated.primary_ip},
            ))

        events.extend(_apply_ports(db, updated.id, host_facts, scan_id, now, observed_subnets, updated))

        # Snapshot the host's post-update state.
        open_ports = [
            {"proto": p.protocol, "port": p.number, "svc": p.service, "ver": p.version}
            for p in db.list_ports(updated.id, only_open=True)
        ]
        db.insert_snapshot(HostSnapshot(
            scan_id=scan_id, host_id=updated.id, ip=updated.primary_ip,
            hostname=updated.hostname, os_detail=updated.os_detail,
            device_type=updated.device_type, open_ports=open_ports,
            captured_at=now,
        ))
```

Replace the `_find_existing_host_id` helper with one that returns the full row:

```python
def _find_existing_host(db: Storage, key: HostKey) -> Host | None:
    if key.mac:
        h = db._find_host_by_mac(key.mac)
        if h:
            return h
    return db._find_host_by_ip(key.ip)
```

Add import: `from netmap.models import HostSnapshot`.

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_correlation.py -v`
Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/correlation.py tests/unit/test_correlation.py
git commit -m "feat(correlation): ip.changed event + per-scan host snapshots"
```

---

## Task 14 — Scanner Protocol + ScanMode enum

**Files:**
- Create: `src/netmap/scanner/base.py`

- [ ] **Step 1: Implement the protocol (no test — Protocol has no runtime behavior to test)**

`src/netmap/scanner/base.py`:
```python
"""Active scanner Protocol and ScanMode enum.

Passive scanners use a different shape (thread + callback) defined in M3.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from enum import Enum
from ipaddress import IPv4Network
from typing import ClassVar, Protocol, runtime_checkable

from netmap.models import Fact


class ScanMode(str, Enum):
    DISCOVER = "discover"
    DEFAULT = "default"
    DEEP = "deep"


@runtime_checkable
class ActiveScanner(Protocol):
    name: ClassVar[str]

    def scan(self, target: IPv4Network, mode: ScanMode) -> AsyncIterator[Fact]:
        """Yield ``Fact`` objects for ``target``."""
        ...
```

- [ ] **Step 2: Commit**

```bash
git add src/netmap/scanner/base.py
git commit -m "feat(scanner): ActiveScanner Protocol + ScanMode enum"
```

---

## Task 15 — nmap XML fixture + parser

**Files:**
- Create: `tests/fixtures/nmap-discover-sample.xml`
- Create: `tests/fixtures/nmap-default-sample.xml`
- Create: `tests/fixtures/nmap-empty.xml`
- Create: `src/netmap/scanner/nmap_scanner.py`
- Create: `tests/unit/test_nmap_scanner.py`

- [ ] **Step 1: Create fixture XMLs**

`tests/fixtures/nmap-empty.xml`:
```xml
<?xml version="1.0"?>
<nmaprun version="7.99">
</nmaprun>
```

`tests/fixtures/nmap-discover-sample.xml`:
```xml
<?xml version="1.0"?>
<nmaprun version="7.99" args="nmap -sn 192.168.1.0/24" start="1748080000">
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.5" addrtype="ipv4"/>
    <address addr="3C:5A:B4:9D:11:E0" addrtype="mac" vendor="Synology Inc."/>
    <hostnames>
      <hostname name="nas.lan" type="PTR"/>
    </hostnames>
  </host>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.42" addrtype="ipv4"/>
    <address addr="A4:5E:60:8B:C1:D2" addrtype="mac" vendor="Apple, Inc."/>
  </host>
</nmaprun>
```

`tests/fixtures/nmap-default-sample.xml`:
```xml
<?xml version="1.0"?>
<nmaprun version="7.99" args="nmap -sS -O --top-ports 100 192.168.1.5" start="1748080000">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.5" addrtype="ipv4"/>
    <address addr="3C:5A:B4:9D:11:E0" addrtype="mac" vendor="Synology Inc."/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.3"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Samba" version="4.17"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 4.x" accuracy="92">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux"/>
      </osmatch>
    </os>
  </host>
</nmaprun>
```

- [ ] **Step 2: Write failing test**

`tests/unit/test_nmap_scanner.py`:
```python
from pathlib import Path

import pytest

from netmap.models import HostnameFact, MacFact, OsFact, PortFact
from netmap.scanner.nmap_scanner import parse_nmap_xml

FIX = Path(__file__).parent.parent / "fixtures"


class TestParseNmapXml:
    def test_empty(self) -> None:
        assert list(parse_nmap_xml((FIX / "nmap-empty.xml").read_text())) == []

    def test_discover_emits_mac_facts(self) -> None:
        facts = list(parse_nmap_xml((FIX / "nmap-discover-sample.xml").read_text()))
        macs = [f for f in facts if isinstance(f, MacFact)]
        assert {(m.mac.upper(), m.ip) for m in macs} == {
            ("3C:5A:B4:9D:11:E0", "192.168.1.5"),
            ("A4:5E:60:8B:C1:D2", "192.168.1.42"),
        }

    def test_discover_emits_hostnames(self) -> None:
        facts = list(parse_nmap_xml((FIX / "nmap-discover-sample.xml").read_text()))
        hostnames = [f for f in facts if isinstance(f, HostnameFact)]
        assert any(h.hostname == "nas.lan" for h in hostnames)

    def test_default_emits_open_ports(self) -> None:
        facts = list(parse_nmap_xml((FIX / "nmap-default-sample.xml").read_text()))
        ports = [f for f in facts if isinstance(f, PortFact) and f.state == "open"]
        assert {(p.proto, p.port, p.service) for p in ports} == {
            ("tcp", 22, "ssh"),
            ("tcp", 445, "microsoft-ds"),
        }

    def test_default_skips_closed_ports(self) -> None:
        facts = list(parse_nmap_xml((FIX / "nmap-default-sample.xml").read_text()))
        ports = [f for f in facts if isinstance(f, PortFact)]
        assert all(p.state == "open" for p in ports)

    def test_default_emits_os(self) -> None:
        facts = list(parse_nmap_xml((FIX / "nmap-default-sample.xml").read_text()))
        os_facts = [f for f in facts if isinstance(f, OsFact)]
        assert any(f.family == "Linux" for f in os_facts)
```

- [ ] **Step 3: Run and confirm failure**

Run: `uv run pytest tests/unit/test_nmap_scanner.py -v`
Expected: ImportError.

- [ ] **Step 4: Implement the parser**

`src/netmap/scanner/nmap_scanner.py`:
```python
"""nmap binary wrapper + XML parser.

The parser is a pure function over XML text — easy to unit-test against fixture
files. The subprocess wrapper is added in Task 16.
"""
from __future__ import annotations

from typing import Iterable
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
        if host_el.findtext("status[@state='up']/.../@state", default=None) is None:
            # robust check: status may not be the first element
            status = host_el.find("status")
            if status is None or status.get("state") != "up":
                continue

        ip = mac = vendor = None
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
            svc_el = port_el.find("service")
            yield PortFact(
                host_key=key,
                proto=port_el.get("protocol"),  # type: ignore[arg-type]
                port=int(port_el.get("portid")),  # type: ignore[arg-type]
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
```

- [ ] **Step 5: Run and confirm pass**

Run: `uv run pytest tests/unit/test_nmap_scanner.py -v`
Expected: 6 passed.

- [ ] **Step 6: Commit**

```bash
git add src/netmap/scanner/nmap_scanner.py tests/unit/test_nmap_scanner.py tests/fixtures/nmap-*.xml
git commit -m "feat(nmap): XML parser emitting MacFact/PortFact/OsFact/HostnameFact/DeviceTypeFact"
```

---

## Task 16 — nmap subprocess wrapper

**Files:**
- Modify: `src/netmap/scanner/nmap_scanner.py`
- Modify: `tests/unit/test_nmap_scanner.py`

- [ ] **Step 1: Append failing test**

```python
import asyncio
import pytest

from netmap.scanner.base import ScanMode
from netmap.scanner.nmap_scanner import NmapScanner, _flags_for_mode


class TestFlagsForMode:
    def test_discover_flags(self) -> None:
        assert _flags_for_mode(ScanMode.DISCOVER) == [
            "-sn", "-PR", "-PE", "-PA80,443", "-T4",
        ]

    def test_default_flags_include_timeout(self) -> None:
        flags = _flags_for_mode(ScanMode.DEFAULT)
        assert "--host-timeout" in flags
        assert "--top-ports" in flags

    def test_deep_flags_full_port_range(self) -> None:
        flags = _flags_for_mode(ScanMode.DEEP)
        assert "-p-" in flags


class TestNmapScannerSubprocess:
    @pytest.mark.asyncio
    async def test_subprocess_failure_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeProc:
            returncode = 1
            async def communicate(self) -> tuple[bytes, bytes]:
                return (b"", b"nmap: bad flags")

        async def fake_exec(*args, **kwargs) -> FakeProc:
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
        from ipaddress import IPv4Network
        scanner = NmapScanner()
        with pytest.raises(RuntimeError, match="bad flags"):
            async for _ in scanner.scan(IPv4Network("127.0.0.1/32"), ScanMode.DISCOVER):
                pass

    @pytest.mark.asyncio
    async def test_subprocess_success_yields_parsed_facts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pathlib import Path
        xml = (Path(__file__).parent.parent / "fixtures" / "nmap-discover-sample.xml").read_bytes()

        class FakeProc:
            returncode = 0
            async def communicate(self) -> tuple[bytes, bytes]:
                return (xml, b"")

        async def fake_exec(*args, **kwargs) -> FakeProc:
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
        from ipaddress import IPv4Network
        scanner = NmapScanner()
        facts = []
        async for f in scanner.scan(IPv4Network("192.168.1.0/24"), ScanMode.DISCOVER):
            facts.append(f)
        assert len(facts) >= 2
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_nmap_scanner.py -v`
Expected: ImportError on `NmapScanner` / `_flags_for_mode`.

- [ ] **Step 3: Implement subprocess wrapper**

Append to `src/netmap/scanner/nmap_scanner.py`:
```python
import asyncio
import shutil
from collections.abc import AsyncIterator
from ipaddress import IPv4Network
from typing import ClassVar

from netmap.scanner.base import ScanMode


def _flags_for_mode(mode: ScanMode) -> list[str]:
    if mode == ScanMode.DISCOVER:
        return ["-sn", "-PR", "-PE", "-PA80,443", "-T4"]
    if mode == ScanMode.DEFAULT:
        return [
            "-sS", "-O", "--top-ports", "100", "-T4",
            "--host-timeout", "5m", "--max-retries", "2",
        ]
    if mode == ScanMode.DEEP:
        return [
            "-sS", "-sV", "-O", "-p-", "-T3",
            "--host-timeout", "30m", "--max-retries", "2",
        ]
    raise ValueError(f"unknown ScanMode: {mode!r}")


class NmapScanner:
    """Subprocess-backed active scanner. Implements ``ActiveScanner``."""

    name: ClassVar[str] = "active.nmap"

    def __init__(self, binary: str | None = None) -> None:
        self._binary = binary or shutil.which("nmap") or "nmap"

    async def scan(
        self, target: IPv4Network, mode: ScanMode
    ) -> AsyncIterator[Fact]:
        flags = _flags_for_mode(mode)
        args = [self._binary, "-oX", "-", *flags, str(target)]
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"nmap exited {proc.returncode}: {stderr.decode().strip()}")
        for fact in parse_nmap_xml(stdout.decode()):
            yield fact
```

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_nmap_scanner.py -v`
Expected: 11 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/scanner/nmap_scanner.py tests/unit/test_nmap_scanner.py
git commit -m "feat(nmap): NmapScanner async subprocess wrapper"
```

---

## Task 17 — ARP scanner

**Files:**
- Create: `src/netmap/scanner/arp_scanner.py`
- Create: `tests/unit/test_arp_scanner.py`

- [ ] **Step 1: Write failing test**

`tests/unit/test_arp_scanner.py`:
```python
from ipaddress import IPv4Network

import pytest

from netmap.models import MacFact
from netmap.scanner.arp_scanner import ArpScanner
from netmap.scanner.base import ScanMode


class TestArpScanner:
    @pytest.mark.asyncio
    async def test_yields_mac_facts_from_srp_results(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeAnswer:
            def __init__(self, hwsrc: str, psrc: str) -> None:
                self.hwsrc = hwsrc
                self.psrc = psrc

        fake_answers = [
            ((None, None), FakeAnswer("aa:bb:cc:dd:ee:01", "192.168.1.5")),
            ((None, None), FakeAnswer("aa:bb:cc:dd:ee:02", "192.168.1.7")),
        ]

        def fake_srp(_pkt, **_kwargs):
            return (fake_answers, [])

        import netmap.scanner.arp_scanner as mod
        monkeypatch.setattr(mod, "srp", fake_srp)

        scanner = ArpScanner(iface="eth0")
        facts = []
        async for f in scanner.scan(IPv4Network("192.168.1.0/24"), ScanMode.DISCOVER):
            facts.append(f)

        assert all(isinstance(f, MacFact) for f in facts)
        assert {f.ip for f in facts} == {"192.168.1.5", "192.168.1.7"}
        assert all(f.src == "active.arp" for f in facts)
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_arp_scanner.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement `ArpScanner`**

`src/netmap/scanner/arp_scanner.py`:
```python
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
```

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_arp_scanner.py -v`
Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/scanner/arp_scanner.py tests/unit/test_arp_scanner.py
git commit -m "feat(arp): ArpScanner wrapping scapy srp via asyncio.to_thread"
```

---

## Task 18 — CLI: `scan` command

**Files:**
- Modify: `src/netmap/cli.py`
- Create: `tests/unit/test_cli.py`

- [ ] **Step 1: Write failing test**

`tests/unit/test_cli.py`:
```python
from typer.testing import CliRunner

from netmap.cli import app

runner = CliRunner()


class TestVersion:
    def test_version_prints(self) -> None:
        r = runner.invoke(app, ["version"])
        assert r.exit_code == 0
        assert "0.1.0" in r.stdout


class TestScanCommand:
    def test_scan_rejects_invalid_target(self, tmp_path) -> None:
        r = runner.invoke(
            app,
            ["scan", "--target", "not-a-cidr", "--mode", "discover",
             "--db", str(tmp_path / "test.db"),
             "--config", str(tmp_path / "config.toml")],
        )
        assert r.exit_code != 0
        assert "parse" in (r.stdout + r.stderr).lower()

    def test_scan_rejects_loopback_without_override(self, tmp_path) -> None:
        r = runner.invoke(
            app,
            ["scan", "--target", "127.0.0.0/8", "--mode", "discover",
             "--db", str(tmp_path / "test.db"),
             "--config", str(tmp_path / "config.toml")],
        )
        assert r.exit_code != 0

    def test_scan_uses_injected_scanners(self, tmp_path, monkeypatch) -> None:
        """Wire a fake scanner pair via the registry to confirm the command
        ingests facts and writes hosts/events."""
        from datetime import datetime, timezone
        from netmap.models import MacFact
        from ipaddress import IPv4Network
        from netmap.scanner.base import ScanMode

        async def fake_scan_nmap(target: IPv4Network, mode: ScanMode):
            if False:
                yield  # pragma: no cover
            return

        async def fake_scan_arp(target: IPv4Network, mode: ScanMode):
            yield MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp")

        from netmap import cli as cli_mod
        monkeypatch.setattr(cli_mod, "_make_nmap_scanner",
                            lambda: type("S", (), {"name": "active.nmap", "scan": staticmethod(fake_scan_nmap)})())
        monkeypatch.setattr(cli_mod, "_make_arp_scanner",
                            lambda iface: type("S", (), {"name": "active.arp", "scan": staticmethod(fake_scan_arp)})())

        db_path = tmp_path / "test.db"
        cfg_path = tmp_path / "config.toml"
        r = runner.invoke(
            app,
            ["scan", "--target", "192.168.1.0/24", "--mode", "discover",
             "--db", str(db_path), "--config", str(cfg_path)],
        )
        assert r.exit_code == 0, r.stdout + r.stderr

        from netmap.storage import Storage
        s = Storage(str(db_path))
        rows = s._conn.execute("SELECT primary_ip FROM host").fetchall()
        assert rows == [("192.168.1.5",)]
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_cli.py -v`
Expected: failures (scan command absent).

- [ ] **Step 3: Implement the `scan` command**

Rewrite `src/netmap/cli.py`:
```python
"""net-map CLI."""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from ipaddress import IPv4Network
from pathlib import Path
from typing import Annotated, Optional

import typer

from netmap import __version__
from netmap.config import DEFAULT_CONFIG_PATH, load_config
from netmap.correlation import correlate
from netmap.models import Scan
from netmap.scanner.arp_scanner import ArpScanner
from netmap.scanner.base import ScanMode
from netmap.scanner.nmap_scanner import NmapScanner
from netmap.scanner.safety import SafetyError, SafetyPolicy, validate_target
from netmap.storage import Storage

app = typer.Typer(help="net-map — continuous inventory + topology visualizer", no_args_is_help=True)

DEFAULT_DB_PATH = Path("~/.netmap/state.db").expanduser()


def _make_nmap_scanner() -> NmapScanner:
    return NmapScanner()


def _make_arp_scanner(iface: str | None) -> ArpScanner:
    return ArpScanner(iface=iface)


@app.command()
def version() -> None:
    """Print the installed netmap version."""
    typer.echo(__version__)


@app.command()
def scan(
    target: Annotated[list[str], typer.Option("--target", "-t", help="CIDR(s) to scan")],
    mode: Annotated[ScanMode, typer.Option("--mode", "-m")] = ScanMode.DISCOVER,
    iface: Annotated[Optional[str], typer.Option("--iface", help="Interface for ARP")] = None,
    db_path: Annotated[Path, typer.Option("--db")] = DEFAULT_DB_PATH,
    config_path: Annotated[Path, typer.Option("--config")] = DEFAULT_CONFIG_PATH,
    i_understand: Annotated[bool, typer.Option("--i-understand", help="Confirm public-IP scan")] = False,
) -> None:
    """Run a single ad-hoc scan against ``--target`` CIDR(s)."""
    cfg = load_config(config_path)
    policy = SafetyPolicy(
        deny_cidrs=tuple(cfg.safety.deny_cidrs),
        allow_public_scan=cfg.safety.allow_public_scan,
        max_target_hosts=cfg.safety.max_target_hosts,
        max_hop_distance=cfg.safety.max_hop_distance,
    )

    nets: list[IPv4Network] = []
    for t in target:
        try:
            nets.append(validate_target(t, policy, confirm=i_understand))
        except SafetyError as exc:
            typer.echo(f"refused: {exc}", err=True)
            raise typer.Exit(code=2)

    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = Storage(str(db_path))
    nmap = _make_nmap_scanner()
    arp = _make_arp_scanner(iface)

    asyncio.run(_run_scan(db, [nmap, arp], nets, mode))


async def _run_scan(
    db: Storage,
    scanners,
    targets: list[IPv4Network],
    mode: ScanMode,
) -> None:
    now = datetime.now(tz=timezone.utc)
    target_str = ",".join(str(t) for t in targets)
    scan_id = db.start_scan(Scan(
        started_at=now, source="cli.scan", target=target_str, mode=mode.value,
        status="running",
    ))
    facts = []
    try:
        for target in targets:
            for scanner in scanners:
                async for f in scanner.scan(target, mode):
                    facts.append(f)
    except Exception as exc:  # surface, finalize, exit non-zero
        db.finish_scan(scan_id, ended_at=datetime.now(tz=timezone.utc),
                       status="error", hosts_seen=0)
        typer.echo(f"scan error: {exc}", err=True)
        raise typer.Exit(code=3)

    events = correlate(
        facts, db, scan_id, now=now,
        observed_subnets=[str(t) for t in targets],
    )
    hosts = db._conn.execute("SELECT COUNT(*) FROM host").fetchone()[0]
    db.finish_scan(scan_id, ended_at=datetime.now(tz=timezone.utc),
                   status="ok", hosts_seen=int(hosts))
    typer.echo(f"scan {scan_id}: {len(facts)} facts → {len(events)} events; {hosts} hosts total")
```

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_cli.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/cli.py tests/unit/test_cli.py
git commit -m "feat(cli): scan command wiring scanners → correlation → storage"
```

---

## Task 19 — CLI: `db` and `config` utility commands

**Files:**
- Modify: `src/netmap/cli.py`
- Modify: `tests/unit/test_cli.py`

- [ ] **Step 1: Append failing tests**

```python
class TestDbCommands:
    def test_db_path(self, tmp_path) -> None:
        db = tmp_path / "x.db"
        r = runner.invoke(app, ["db", "path", "--db", str(db)])
        assert r.exit_code == 0
        assert str(db) in r.stdout

    def test_db_vacuum(self, tmp_path) -> None:
        from netmap.storage import Storage
        db = tmp_path / "x.db"
        Storage(str(db)).close()
        r = runner.invoke(app, ["db", "vacuum", "--db", str(db)])
        assert r.exit_code == 0

    def test_db_reset_requires_flag(self, tmp_path) -> None:
        from netmap.storage import Storage
        db = tmp_path / "x.db"
        Storage(str(db)).close()
        r = runner.invoke(app, ["db", "reset", "--db", str(db)])
        assert r.exit_code != 0

    def test_db_reset_with_flag(self, tmp_path) -> None:
        from netmap.storage import Storage
        db = tmp_path / "x.db"
        Storage(str(db)).close()
        r = runner.invoke(app, ["db", "reset", "--db", str(db), "--yes-really-delete"])
        assert r.exit_code == 0
        assert not db.exists()


class TestConfigCommands:
    def test_config_show(self, tmp_path) -> None:
        cfg = tmp_path / "config.toml"
        r = runner.invoke(app, ["config", "show", "--config", str(cfg)])
        assert r.exit_code == 0
        assert "interval_s" in r.stdout
```

- [ ] **Step 2: Run and confirm failure**

Run: `uv run pytest tests/unit/test_cli.py -v`
Expected: failures on the new commands.

- [ ] **Step 3: Add commands**

Append to `src/netmap/cli.py`:
```python
db_app = typer.Typer(help="Database utilities")
config_app = typer.Typer(help="Configuration")
app.add_typer(db_app, name="db")
app.add_typer(config_app, name="config")


@db_app.command("path")
def db_path_cmd(db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB_PATH) -> None:
    """Print the resolved database path."""
    typer.echo(str(db))


@db_app.command("vacuum")
def db_vacuum_cmd(db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB_PATH) -> None:
    """Run SQLite VACUUM."""
    s = Storage(str(db))
    s._conn.execute("VACUUM")
    s.close()


@db_app.command("reset")
def db_reset_cmd(
    db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB_PATH,
    yes: Annotated[bool, typer.Option("--yes-really-delete")] = False,
) -> None:
    """Delete the database file. Requires --yes-really-delete."""
    if not yes:
        typer.echo("refusing to delete; pass --yes-really-delete to confirm", err=True)
        raise typer.Exit(code=2)
    if db.exists():
        db.unlink()


@db_app.command("migrate")
def db_migrate_cmd(db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB_PATH) -> None:
    """Run idempotent schema bootstrap (no-op if already current)."""
    Storage(str(db)).close()


@config_app.command("show")
def config_show_cmd(config: Annotated[Path, typer.Option("--config")] = DEFAULT_CONFIG_PATH) -> None:
    """Print the resolved configuration as JSON."""
    import json as _json
    cfg = load_config(config)
    typer.echo(_json.dumps(cfg.model_dump(), indent=2, default=str))
```

- [ ] **Step 4: Run and confirm pass**

Run: `uv run pytest tests/unit/test_cli.py -v`
Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/cli.py tests/unit/test_cli.py
git commit -m "feat(cli): db {path,vacuum,reset,migrate} + config show"
```

---

## Task 20 — Integration smoke test against `127.0.0.1`

**Files:**
- Create: `tests/integration/test_scan_smoke.py`

- [ ] **Step 1: Write the integration test (uses `--allow-loopback`)**

```python
"""End-to-end smoke test.

Boots a Python HTTP server on a random localhost port, invokes ``netmap scan``
against ``127.0.0.1/32`` in ``default`` mode, asserts the host + port land in
the DB. Requires the ``nmap`` binary and root/CAP_NET_RAW for SYN scans;
skipped otherwise.
"""
from __future__ import annotations

import http.server
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _can_run_nmap() -> bool:
    if shutil.which("nmap") is None:
        return False
    if os.geteuid() != 0:
        return False
    return True


@pytest.fixture
def http_server():
    port = _free_port()
    handler = http.server.SimpleHTTPRequestHandler
    srv = socketserver.TCPServer(("127.0.0.1", port), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()


@pytest.mark.skipif(not _can_run_nmap(), reason="nmap not available or not root")
def test_default_scan_finds_local_http(tmp_path: Path, http_server: int) -> None:
    db = tmp_path / "smoke.db"
    cfg = tmp_path / "config.toml"

    proc = subprocess.run(
        [
            sys.executable, "-m", "netmap", "scan",
            "--target", "127.0.0.1/32",
            "--mode", "default",
            "--allow-loopback",
            "--db", str(db),
            "--config", str(cfg),
        ],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr

    import sqlite3
    conn = sqlite3.connect(str(db))
    ports = conn.execute("SELECT number FROM port WHERE state='open'").fetchall()
    assert (http_server,) in ports, f"expected open port {http_server} in {ports}"
```

- [ ] **Step 2: Run and confirm failure**

Run: `sudo -E uv run pytest tests/integration/test_scan_smoke.py -v -m integration`
Expected (on a root box with nmap): FAIL — unknown option `--allow-loopback`. (Without root/nmap: skipped.)

- [ ] **Step 3: Add the `--allow-loopback` flag to the `scan` command**

Edit `src/netmap/cli.py`'s `scan` function — add the flag and route it through `validate_target`:

```python
@app.command()
def scan(
    target: Annotated[list[str], typer.Option("--target", "-t", help="CIDR(s) to scan")],
    mode: Annotated[ScanMode, typer.Option("--mode", "-m")] = ScanMode.DISCOVER,
    iface: Annotated[Optional[str], typer.Option("--iface")] = None,
    db_path: Annotated[Path, typer.Option("--db")] = DEFAULT_DB_PATH,
    config_path: Annotated[Path, typer.Option("--config")] = DEFAULT_CONFIG_PATH,
    i_understand: Annotated[bool, typer.Option("--i-understand")] = False,
    allow_loopback: Annotated[bool, typer.Option(
        "--allow-loopback", hidden=True,
        help="Smoke-test escape hatch — overrides deny_cidrs for the supplied targets.",
    )] = False,
) -> None:
    ...
    for t in target:
        try:
            nets.append(validate_target(
                t, policy, confirm=i_understand, override_deny=allow_loopback,
            ))
        except SafetyError as exc:
            typer.echo(f"refused: {exc}", err=True)
            raise typer.Exit(code=2)
    ...
```

- [ ] **Step 4: Run and confirm pass**

Run: `sudo -E uv run pytest tests/integration/test_scan_smoke.py -v -m integration`
Expected: passed (root + nmap available) or skipped (otherwise).

- [ ] **Step 5: Commit**

```bash
git add tests/integration/test_scan_smoke.py src/netmap/cli.py
git commit -m "test(integration): smoke scan of 127.0.0.1; add hidden --allow-loopback escape hatch"
```

---

## Task 21 — README skeleton

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write the README**

`README.md`:
```markdown
# net-map

Continuous inventory and topology visualizer for local networks. Wraps `nmap` and `scapy` ARP for active discovery; passive sniffing and a web UI land in M2/M3.

## Status

**M1 — Foundation + CLI scanner.** You can run a one-shot scan from the command line and persist the results in SQLite. The continuous loop and web UI are next.

See [`docs/superpowers/specs/2026-05-25-netmap-design.md`](docs/superpowers/specs/2026-05-25-netmap-design.md) for the full v1 design, and [`docs/ROADMAP.md`](docs/ROADMAP.md) for the v2+ direction (vuln scanning, exploit scoring).

## Requirements

- Linux (M1 first-class; macOS untested)
- Python ≥3.13
- [`uv`](https://docs.astral.sh/uv/)
- `nmap` binary on `$PATH`
- Root or `CAP_NET_RAW + CAP_NET_ADMIN` for SYN scans / ARP

## Install

```bash
git clone https://github.com/samouraifox/net-map
cd net-map
uv sync --extra dev
```

## Use

Discovery sweep of your local /24:
```bash
sudo uv run netmap scan --target 192.168.1.0/24 --mode discover
```

Top-100 ports + OS detection on a single host:
```bash
sudo uv run netmap scan --target 192.168.1.5/32 --mode default
```

Show the database location:
```bash
uv run netmap db path
```

Inspect the configuration:
```bash
uv run netmap config show
```

## Develop

```bash
uv run pytest                 # unit + API tests
uv run pytest -m integration  # smoke tests (need nmap + root)
uv run ruff check src tests
```

## License

MIT.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README with M1 install + usage"
```

---

## Task 22 — GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the workflow**

`.github/workflows/ci.yml`:
```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v3

      - name: Install Python 3.13
        run: uv python install 3.13

      - name: Install deps
        run: uv sync --extra dev

      - name: Lint
        run: uv run ruff check src tests

      - name: Unit + API tests
        run: uv run pytest -m "not integration"
```

- [ ] **Step 2: Commit and push**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: GitHub Actions running ruff + unit/API tests on push and PR"
git push origin main
```

- [ ] **Step 3: Verify the workflow ran**

Visit `https://github.com/samouraifox/net-map/actions` — expect a green run.

---

## Self-review checklist (run BEFORE handing off)

Before declaring M1 complete, the implementer must:

1. **Run the full suite:** `uv run pytest` — every test in `tests/unit/` and `tests/integration/` passes (integration can be skipped on a dev box without root).
2. **Lint clean:** `uv run ruff check src tests` exits 0.
3. **Manual smoke:** as root, on a real LAN, run `sudo uv run netmap scan --target <your-/24> --mode discover` — confirm hosts appear in the SQLite DB and the CLI prints a non-zero `hosts_seen` count.
4. **DB schema matches spec:** `sqlite3 ~/.netmap/state.db ".schema"` shows all tables from §7.2 of the spec.
5. **Behavior matches spec table for nmap modes:** `_flags_for_mode` returns flags matching §8.2.

If any of these fail, do not declare M1 done — surface the gap.

## Spec coverage (M1 portion)

| Spec section                | M1 task                                |
|-----------------------------|----------------------------------------|
| §6 Repo layout (M1 subset)  | Task 1 + scaffolding throughout        |
| §7 Data model               | Tasks 2–3 (models), 7–10 (storage)     |
| §8.1 Adapter Protocols      | Task 14 (ActiveScanner)                |
| §8.2 nmap modes + parsing   | Tasks 15–16                            |
| §8.3 ARP scanner            | Task 17                                |
| §8.6 Correlation            | Tasks 11–13                            |
| §11 CLI `scan` + `db` + `config show` | Tasks 18–19                  |
| §12 Config file             | Task 6                                 |
| §13.2 Target validation     | Task 5                                 |
| §14.1 Unit tests            | All tasks (TDD throughout)             |
| §14.2 Integration smoke     | Task 20                                |
| §14.4 CI                    | Task 22                                |

**Deferred to M2:** §8.4 passive sniffer, §5.1 scan loop, §9 Web API, §10 Frontend, §13.1 privilege check on startup banner (we lean on nmap/scapy's own errors for now).
**Deferred to M3:** §8.5 gateway traversal, retention GC, runtime config mutation, `netmap diff`/`export`/`update-oui`/`config set`/`subnets ...`.
