# net-map M2 — Web UI + Foreground Scan Loop · Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **The maintainer's preference for this project:** Opus subagents (high/xhigh) execute reflection-heavy tasks (loop, correlation wiring, lifespan); Sonnet subagents execute mechanical scaffolding (storage helpers, schemas, route boilerplate, UI files); Sonnet runs the per-task spec + code-quality reviews; a final Opus pass reviews the entire PR for code health. Do not implement inline from a max-effort planning session.

**Goal:** Ship `sudo netmap up` — a single-process FastAPI server that runs a foreground asyncio scan loop, serves a vanilla-JS web UI, and streams live updates over SSE. The CLI auto-detects the local subnet, the UI renders a subnet-grouped Cytoscape graph with device-type icons, and Ctrl-C stops everything cleanly.

**Architecture:** Single Python process. FastAPI `lifespan` owns Storage, AsyncBus, the scan loop task, and uvicorn. No threads beyond what M1 already uses (subprocess for nmap, `asyncio.to_thread` for scapy ARP). The schema is unchanged from M1 — M2 adds `scan.started`/`scan.ok`/`scan.error`/`scan.skipped` as new `event.kind` values into the existing free-text column. Frontend is vanilla HTML + CSS + JS with Cytoscape via CDN — no build step, no node toolchain.

**Tech stack:** Python ≥3.13, FastAPI ≥0.115, uvicorn[standard] ≥0.32, sse-starlette ≥2.1, httpx ≥0.28 (test client). Cytoscape.js 3.30 + cose-bilkent 4.1 via CDN. Geist Mono via Google Fonts. Lucide-style icons inlined as a single SVG sprite in `index.html`.

**Spec reference:** `docs/superpowers/specs/2026-05-25-netmap-m2-design.md` is the source of truth. If anything below contradicts the spec, the spec wins — flag and ask.

**Scope deferred:**
- **M3:** passive sniffer, gateway traversal + `POST /api/v1/subnets/discover`, mutation endpoints (`PATCH /hosts/{id}`, `POST/PATCH/DELETE /subnets`, `PATCH /config`), non-loopback bind + bearer-token auth, layout switcher, retention GC, `netmap diff/export/update-oui/config set/subnets ...`.
- **v2+ (ROADMAP):** vulnerability awareness, CVE lookup, EPSS/KEV.

---

## File structure (M2)

```
net-map/
├── pyproject.toml                  # +fastapi, +uvicorn, +sse-starlette, +httpx; extend force-include for src/netmap/ui/
├── src/netmap/
│   ├── cli.py                      # +up command
│   ├── storage.py                  # +list_subnets, list_scans, list_host_summaries, get_host, list_recent_events
│   ├── scanner/
│   │   ├── nmap_scanner.py         # _flags_for_mode now takes timeouts; NmapScanner accepts default/deep timeouts
│   │   └── loop.py                 # NEW — scan_loop coroutine + maybe_run dispatcher
│   ├── server/
│   │   ├── __init__.py             # NEW
│   │   ├── app.py                  # NEW — FastAPI app + lifespan + create_app/run
│   │   ├── routes.py               # NEW — REST endpoints
│   │   ├── events.py               # NEW — AsyncBus + EventOut serialization
│   │   ├── schemas.py              # NEW — HostSummary, HostDetail, HostIp, ScanRequest, ScanResponse
│   │   ├── subnet_bootstrap.py     # NEW — parse `ip route` + insert local CIDR
│   │   └── privilege.py            # NEW — startup capability + nmap-binary + bind checks
│   └── ui/                         # NEW — bundled into wheel via force-include
│       ├── index.html              # shell + CDN script/link + inlined SVG <symbol> icon defs
│       ├── styles.css              # palette tokens + layout + components
│       └── app.js                  # state + API client + Cytoscape + SSE + DOM render
└── tests/
    ├── unit/
    │   ├── test_storage_m2.py      # NEW — list_subnets, list_host_summaries, etc.
    │   ├── test_nmap_timeouts.py   # NEW — _flags_for_mode with config-driven timeouts
    │   ├── test_privilege.py       # NEW
    │   ├── test_subnet_bootstrap.py # NEW
    │   ├── test_events_bus.py      # NEW
    │   └── test_loop.py            # NEW
    ├── api/
    │   ├── __init__.py             # NEW
    │   ├── conftest.py             # NEW — TestClient fixture against in-memory app
    │   ├── test_hosts.py           # NEW
    │   ├── test_subnets.py         # NEW
    │   ├── test_scans.py           # NEW
    │   ├── test_events.py          # NEW
    │   ├── test_sse.py             # NEW
    │   └── test_static.py          # NEW
    └── integration/
        └── test_up_smoke.py        # NEW — spawn netmap up; drive via HTTP; assert SSE; SIGINT exit
```

Boundaries: `server/` is purely web-layer (FastAPI routes, schemas, lifespan, bus); `scanner/loop.py` owns scan dispatch and cadence; existing `correlation.py` and `scanner/{nmap_scanner,arp_scanner,safety}.py` keep their M1 responsibilities. `ui/*` is static text bundled into the wheel.

---

## Phase 1 — Foundation (Tasks 1-6)

These tasks add the M2 dependencies, extend the Storage layer with the listing helpers the API and bootstrap need, and close one M1-review followup (wiring host-timeout config through NmapScanner). No new modules yet — every change is to a file that already exists.

### Task 1 — Add M2 dependencies and scaffold the new package directories

**Files:**
- Modify: `pyproject.toml`
- Create: `src/netmap/server/__init__.py`
- Create: `src/netmap/scanner/loop.py` (empty stub for now)
- Create: `src/netmap/ui/.gitkeep`
- Create: `tests/api/__init__.py`

- [ ] **Step 1: Add the runtime + test deps to `pyproject.toml`**

Modify `pyproject.toml` — replace the existing `[project]` and `[project.optional-dependencies]` and `[tool.hatch.build.targets.wheel.force-include]` sections so the file reads:

```toml
[project]
name = "netmap"
version = "0.2.0"
description = "Continuous inventory + topology visualizer for local networks"
requires-python = ">=3.13"
authors = [{ name = "Aymen", email = "aymen09112004@gmail.com" }]
readme = "README.md"
license = { text = "MIT" }
dependencies = [
    "typer>=0.16.0",
    "pydantic>=2.9",
    "scapy>=2.6",
    "fastapi>=0.115",
    "uvicorn[standard]>=0.32",
    "sse-starlette>=2.1",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.3",
    "pytest-asyncio>=0.24",
    "pytest-mock>=3.14",
    "anyio>=4.6",
    "httpx>=0.28",
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
"src/netmap/ui" = "netmap/ui"

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

The version bump (0.1.0 → 0.2.0) signals M2.

- [ ] **Step 2: Create empty server package + loop stub + ui placeholder + api test dir**

`src/netmap/server/__init__.py`:
```python
"""Web server package — FastAPI app, routes, SSE bus, schemas, startup checks."""
```

`src/netmap/scanner/loop.py`:
```python
"""Foreground asyncio scan loop + per-scan dispatcher.

`scan_loop` runs while the process is alive and ticks on `cfg.scan.interval_s`.
`maybe_run` opens a scan row, registers the (mode, target) pair in the
in-flight set, and dispatches the actual scan work as a background task.
"""
```

Empty file: `src/netmap/ui/.gitkeep`.

`tests/api/__init__.py` (empty).

- [ ] **Step 3: Bump `__version__` to match pyproject**

Modify `src/netmap/__init__.py` so it reads:
```python
__version__ = "0.2.0"
```

- [ ] **Step 4: Sync deps and verify the package still imports + tests still pass**

Run:
```bash
uv sync --extra dev
uv run python -c "import fastapi, uvicorn, sse_starlette; print('ok')"
uv run pytest -m "not integration" -q
```
Expected: deps install, the import line prints `ok`, all existing M1 tests still pass (99 passed).

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml uv.lock src/netmap/__init__.py src/netmap/server/__init__.py src/netmap/scanner/loop.py src/netmap/ui/.gitkeep tests/api/__init__.py
git commit -m "chore(m2): add fastapi/uvicorn/sse-starlette deps + scaffold server/loop/ui dirs"
```

---

### Task 2 — Storage: `list_subnets()`

**Files:**
- Modify: `src/netmap/storage.py` (add method after `get_subnet_by_cidr`)
- Create: `tests/unit/test_storage_m2.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_storage_m2.py`:
```python
"""Tests for storage helpers added in M2."""
from __future__ import annotations

from datetime import UTC, datetime

from netmap.models import Subnet
from netmap.storage import Storage


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=UTC)


def test_list_subnets_returns_all_rows_ordered_by_id():
    db = Storage(":memory:")
    db.insert_subnet(Subnet(
        cidr="192.168.1.0/24", source="config", enabled=True,
        hop_distance=0, first_seen=_ts("2026-05-25T10:00:00"),
    ))
    db.insert_subnet(Subnet(
        cidr="10.0.0.0/24", source="discovered", enabled=False,
        hop_distance=1, first_seen=_ts("2026-05-25T10:01:00"),
    ))

    rows = db.list_subnets()

    assert [s.cidr for s in rows] == ["192.168.1.0/24", "10.0.0.0/24"]
    assert rows[0].source == "config" and rows[0].enabled is True
    assert rows[1].source == "discovered" and rows[1].enabled is False
    assert rows[1].hop_distance == 1
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_storage_m2.py::test_list_subnets_returns_all_rows_ordered_by_id -v`
Expected: FAIL with `AttributeError: 'Storage' object has no attribute 'list_subnets'`.

- [ ] **Step 3: Implement `list_subnets`**

In `src/netmap/storage.py`, immediately after the `get_subnet_by_cidr` method, add:

```python
    def list_subnets(self) -> list[Subnet]:
        rows = self._conn.execute(
            "SELECT id, cidr, label, source, enabled, hop_distance, first_seen "
            "FROM subnet ORDER BY id"
        ).fetchall()
        return [
            Subnet(
                id=r[0], cidr=r[1], label=r[2], source=r[3],
                enabled=bool(r[4]), hop_distance=r[5],
                first_seen=datetime.fromisoformat(r[6]),
            )
            for r in rows
        ]
```

- [ ] **Step 4: Re-run the test**

Run: `uv run pytest tests/unit/test_storage_m2.py::test_list_subnets_returns_all_rows_ordered_by_id -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/storage.py tests/unit/test_storage_m2.py
git commit -m "feat(storage): add list_subnets()"
```

---

### Task 3 — Storage: `list_host_summaries()` with subnet + q filters + open_port_count

**Files:**
- Modify: `src/netmap/storage.py`
- Modify: `tests/unit/test_storage_m2.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_storage_m2.py`:

```python
from netmap.models import Host, Port


def _make_host(db: Storage, *, mac: str | None, ip: str, hostname: str | None = None,
                vendor: str | None = None) -> int:
    now = _ts("2026-05-25T10:00:00")
    h = db.upsert_host(Host(
        mac=mac, primary_ip=ip, hostname=hostname, vendor=vendor,
        first_seen=now, last_seen=now,
    ))
    assert h.id is not None
    return h.id


def _add_port(db: Storage, host_id: int, port: int, state: str = "open") -> None:
    now = _ts("2026-05-25T10:00:00")
    db.upsert_port(Port(
        host_id=host_id, protocol="tcp", number=port, state=state,
        first_seen=now, last_seen=now,
    ))


def test_list_host_summaries_returns_open_port_count():
    db = Storage(":memory:")
    a = _make_host(db, mac="aa:bb:cc:dd:ee:01", ip="192.168.1.10")
    b = _make_host(db, mac="aa:bb:cc:dd:ee:02", ip="192.168.1.11")
    _add_port(db, a, 22, "open")
    _add_port(db, a, 80, "open")
    _add_port(db, a, 9999, "closed")
    _add_port(db, b, 443, "open")

    rows = db.list_host_summaries()

    by_ip = {r["primary_ip"]: r for r in rows}
    assert by_ip["192.168.1.10"]["open_port_count"] == 2
    assert by_ip["192.168.1.11"]["open_port_count"] == 1


def test_list_host_summaries_filters_by_q_against_hostname_ip_mac_vendor():
    db = Storage(":memory:")
    _make_host(db, mac="aa:bb:cc:dd:ee:01", ip="192.168.1.10",
               hostname="printer-lobby", vendor="Brother Industries")
    _make_host(db, mac="aa:bb:cc:dd:ee:02", ip="192.168.1.11",
               hostname="laptop-aymen", vendor="Apple")

    by_hostname = db.list_host_summaries(q="printer")
    assert [r["primary_ip"] for r in by_hostname] == ["192.168.1.10"]

    by_ip = db.list_host_summaries(q="1.11")
    assert [r["primary_ip"] for r in by_ip] == ["192.168.1.11"]

    by_vendor = db.list_host_summaries(q="apple")
    assert [r["primary_ip"] for r in by_vendor] == ["192.168.1.11"]


def test_list_host_summaries_filters_by_subnet_membership():
    db = Storage(":memory:")
    db.insert_subnet(Subnet(
        cidr="192.168.1.0/24", source="config", enabled=True,
        hop_distance=0, first_seen=_ts("2026-05-25T10:00:00"),
    ))
    sid = db.get_subnet_by_cidr("192.168.1.0/24").id
    _make_host(db, mac="aa:bb:cc:dd:ee:01", ip="192.168.1.10")
    _make_host(db, mac="aa:bb:cc:dd:ee:02", ip="10.0.0.5")

    rows = db.list_host_summaries(subnet_id=sid)

    assert [r["primary_ip"] for r in rows] == ["192.168.1.10"]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/test_storage_m2.py -v -k "list_host_summaries"`
Expected: FAIL with `AttributeError: 'Storage' object has no attribute 'list_host_summaries'`.

- [ ] **Step 3: Implement `list_host_summaries`**

In `src/netmap/storage.py`, after `_upsert_host_ip`, add:

```python
    def list_host_summaries(
        self,
        *,
        subnet_id: int | None = None,
        q: str | None = None,
    ) -> list[dict]:
        """Return a list of dicts shaped for the GET /hosts API.

        Columns: id, mac, primary_ip, hostname, vendor, device_type, trusted,
        open_port_count, last_seen. The subnet filter matches the host's
        primary_ip against the subnet CIDR via SQLite-side check. The q filter
        is a case-insensitive substring against mac, primary_ip, hostname, vendor.
        """
        sql = (
            "SELECT h.id, h.mac, h.primary_ip, h.hostname, h.vendor, "
            "h.device_type, h.trusted, h.last_seen, "
            "COALESCE(SUM(CASE WHEN p.state='open' THEN 1 ELSE 0 END), 0) "
            "FROM host h LEFT JOIN port p ON p.host_id = h.id "
            "WHERE 1=1"
        )
        params: list[object] = []
        if q:
            sql += (
                " AND (lower(COALESCE(h.mac,''))      LIKE ?"
                "   OR lower(h.primary_ip)            LIKE ?"
                "   OR lower(COALESCE(h.hostname,'')) LIKE ?"
                "   OR lower(COALESCE(h.vendor,''))   LIKE ?)"
            )
            pattern = f"%{q.lower()}%"
            params.extend([pattern, pattern, pattern, pattern])
        sql += " GROUP BY h.id ORDER BY h.id"

        rows = self._conn.execute(sql, params).fetchall()

        result: list[dict] = []
        for r in rows:
            result.append({
                "id": r[0], "mac": r[1], "primary_ip": r[2],
                "hostname": r[3], "vendor": r[4], "device_type": r[5],
                "trusted": bool(r[6]), "last_seen": r[7],
                "open_port_count": int(r[8]),
            })

        if subnet_id is not None:
            cidr_row = self._conn.execute(
                "SELECT cidr FROM subnet WHERE id=?", (subnet_id,)
            ).fetchone()
            if not cidr_row:
                return []
            from ipaddress import IPv4Address, IPv4Network
            net = IPv4Network(cidr_row[0])
            result = [
                r for r in result
                if _ip_in_net_safe(r["primary_ip"], net)
            ]
        return result
```

Also add at module scope (just below the `_iso` helper near the top of the file):

```python
def _ip_in_net_safe(ip: str, net) -> bool:
    from ipaddress import AddressValueError, IPv4Address
    try:
        return IPv4Address(ip) in net
    except (AddressValueError, ValueError):
        return False
```

- [ ] **Step 4: Re-run the tests**

Run: `uv run pytest tests/unit/test_storage_m2.py -v`
Expected: all four tests in the file PASS.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/storage.py tests/unit/test_storage_m2.py
git commit -m "feat(storage): add list_host_summaries() with subnet + q filters"
```

---

### Task 4 — Storage: `get_host(id)` and `list_recent_events(host_id, limit)`

**Files:**
- Modify: `src/netmap/storage.py`
- Modify: `tests/unit/test_storage_m2.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_storage_m2.py`:

```python
from netmap.models import Event


def test_get_host_returns_dto_or_none():
    db = Storage(":memory:")
    hid = _make_host(db, mac="aa:bb:cc:dd:ee:01", ip="192.168.1.10",
                     hostname="printer-lobby")

    h = db.get_host(hid)
    assert h is not None
    assert h.primary_ip == "192.168.1.10"
    assert h.hostname == "printer-lobby"

    assert db.get_host(9999) is None


def test_list_recent_events_filters_by_host_id_and_limit():
    db = Storage(":memory:")
    hid = _make_host(db, mac="aa:bb:cc:dd:ee:01", ip="192.168.1.10")
    other = _make_host(db, mac="aa:bb:cc:dd:ee:02", ip="192.168.1.11")
    base = _ts("2026-05-25T10:00:00")
    for i in range(5):
        db.insert_event(Event(
            ts=base.replace(second=i), host_id=hid, kind="port.opened",
            payload={"port": 80 + i},
        ))
    db.insert_event(Event(
        ts=base, host_id=other, kind="host.new", payload=None,
    ))

    rows = db.list_recent_events(host_id=hid, limit=3)
    assert len(rows) == 3
    assert all(e.host_id == hid for e in rows)
    assert [e.payload["port"] for e in rows] == [84, 83, 82]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/test_storage_m2.py -v -k "get_host or list_recent_events"`
Expected: FAIL with missing attributes.

- [ ] **Step 3: Implement `get_host` + `list_recent_events`**

In `src/netmap/storage.py`, immediately after `_find_host_by_ip`, add:

```python
    def get_host(self, host_id: int) -> Host | None:
        row = self._conn.execute(
            self._SELECT_HOST + " WHERE id=?", (host_id,)
        ).fetchone()
        return self._row_to_host(row) if row else None
```

Then near the bottom of the file, immediately after `list_events`, add:

```python
    def list_recent_events(
        self, *, host_id: int, limit: int = 50,
    ) -> list[Event]:
        rows = self._conn.execute(
            "SELECT id, ts, scan_id, host_id, kind, payload FROM event "
            "WHERE host_id=? ORDER BY ts DESC LIMIT ?",
            (host_id, limit),
        ).fetchall()
        return [
            Event(
                id=r[0], ts=datetime.fromisoformat(r[1]), scan_id=r[2],
                host_id=r[3], kind=r[4],
                payload=json.loads(r[5]) if r[5] else None,
            )
            for r in rows
        ]
```

- [ ] **Step 4: Re-run the tests**

Run: `uv run pytest tests/unit/test_storage_m2.py -v`
Expected: all six tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/storage.py tests/unit/test_storage_m2.py
git commit -m "feat(storage): add get_host() and list_recent_events()"
```

---

### Task 5 — Storage: `list_scans()` with status / since / limit filters

**Files:**
- Modify: `src/netmap/storage.py`
- Modify: `tests/unit/test_storage_m2.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_storage_m2.py`:

```python
from netmap.models import Scan


def test_list_scans_orders_newest_first_and_respects_limit():
    db = Storage(":memory:")
    base = _ts("2026-05-25T10:00:00")
    for i in range(5):
        db.start_scan(Scan(
            started_at=base.replace(minute=i), source="cli.scan",
            target="192.168.1.0/24", mode="discover", status="ok",
            hosts_seen=10,
        ))

    rows = db.list_scans(limit=3)

    assert len(rows) == 3
    assert rows[0].started_at > rows[1].started_at > rows[2].started_at


def test_list_scans_filters_by_status_and_since():
    db = Storage(":memory:")
    base = _ts("2026-05-25T10:00:00")
    db.start_scan(Scan(
        started_at=base, source="cli.scan", target="x", mode="discover",
        status="error", hosts_seen=0,
    ))
    ok_id = db.start_scan(Scan(
        started_at=base.replace(minute=5), source="cli.scan", target="x",
        mode="discover", status="ok", hosts_seen=3,
    ))

    only_ok = db.list_scans(status="ok")
    assert [s.id for s in only_ok] == [ok_id]

    after = db.list_scans(since=base.replace(minute=3))
    assert [s.id for s in after] == [ok_id]
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/unit/test_storage_m2.py -v -k "list_scans"`
Expected: FAIL — `list_scans` does not exist.

- [ ] **Step 3: Implement `list_scans`**

In `src/netmap/storage.py`, immediately after `get_scan`, add:

```python
    def list_scans(
        self,
        *,
        status: str | None = None,
        since: datetime | None = None,
        limit: int = 50,
    ) -> list[Scan]:
        sql = (
            "SELECT id, started_at, ended_at, source, target, mode, status, "
            "hosts_seen, notes FROM scan WHERE 1=1"
        )
        params: list[object] = []
        if status:
            sql += " AND status=?"
            params.append(status)
        if since:
            sql += " AND started_at >= ?"
            params.append(_iso(since))
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(sql, params).fetchall()
        return [
            Scan(
                id=r[0],
                started_at=datetime.fromisoformat(r[1]),
                ended_at=datetime.fromisoformat(r[2]) if r[2] else None,
                source=r[3], target=r[4], mode=r[5], status=r[6],
                hosts_seen=r[7], notes=r[8],
            )
            for r in rows
        ]
```

- [ ] **Step 4: Re-run the tests**

Run: `uv run pytest tests/unit/test_storage_m2.py -v`
Expected: all eight tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/storage.py tests/unit/test_storage_m2.py
git commit -m "feat(storage): add list_scans() with status/since/limit filters"
```

---

### Task 6 — Wire `NmapScanner` host timeouts from config

**Files:**
- Modify: `src/netmap/scanner/nmap_scanner.py`
- Modify: `src/netmap/cli.py` (update call site)
- Create: `tests/unit/test_nmap_timeouts.py`

This closes the M1 review followup: `_flags_for_mode` currently hardcodes `--host-timeout 5m` / `30m`. M2 routes these through `cfg.scan.default_scan_host_timeout` and `cfg.scan.deep_scan_host_timeout`.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_nmap_timeouts.py`:
```python
"""NmapScanner accepts host-timeout values from config and threads them into nmap flags."""
from __future__ import annotations

from netmap.scanner.base import ScanMode
from netmap.scanner.nmap_scanner import NmapScanner, _flags_for_mode


def test_flags_for_mode_default_uses_provided_timeout():
    flags = _flags_for_mode(
        ScanMode.DEFAULT,
        default_host_timeout="2m",
        deep_host_timeout="20m",
    )
    assert "--host-timeout" in flags
    assert flags[flags.index("--host-timeout") + 1] == "2m"


def test_flags_for_mode_deep_uses_provided_deep_timeout():
    flags = _flags_for_mode(
        ScanMode.DEEP,
        default_host_timeout="2m",
        deep_host_timeout="20m",
    )
    assert flags[flags.index("--host-timeout") + 1] == "20m"


def test_flags_for_mode_discover_has_no_host_timeout():
    flags = _flags_for_mode(
        ScanMode.DISCOVER,
        default_host_timeout="2m",
        deep_host_timeout="20m",
    )
    assert "--host-timeout" not in flags


def test_nmap_scanner_constructor_accepts_timeouts():
    s = NmapScanner(
        default_host_timeout="3m",
        deep_host_timeout="25m",
    )
    assert s._default_host_timeout == "3m"
    assert s._deep_host_timeout == "25m"
```

- [ ] **Step 2: Run the test**

Run: `uv run pytest tests/unit/test_nmap_timeouts.py -v`
Expected: FAIL — `_flags_for_mode` takes only a mode arg, and `NmapScanner` doesn't accept timeouts.

- [ ] **Step 3: Update `_flags_for_mode` and `NmapScanner`**

Replace the body of `src/netmap/scanner/nmap_scanner.py` from `def _flags_for_mode(...)` through the end of `class NmapScanner` with:

```python
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
```

- [ ] **Step 4: Update the CLI call site**

In `src/netmap/cli.py`, find the `_make_nmap_scanner` function. Replace it with a config-aware version:

Replace:
```python
def _make_nmap_scanner() -> NmapScanner:
    return NmapScanner()
```

With:
```python
def _make_nmap_scanner(cfg) -> NmapScanner:
    return NmapScanner(
        default_host_timeout=cfg.scan.default_scan_host_timeout,
        deep_host_timeout=cfg.scan.deep_scan_host_timeout,
    )
```

And in the `scan` function, update the call site. Find this line:
```python
    nmap = _make_nmap_scanner()
```
Replace with:
```python
    nmap = _make_nmap_scanner(cfg)
```

- [ ] **Step 5: Run all tests**

Run: `uv run pytest -m "not integration" -q`
Expected: all tests PASS including the 4 new ones in `tests/unit/test_nmap_timeouts.py`. Total should now be ~107 passing.

- [ ] **Step 6: Commit**

```bash
git add src/netmap/scanner/nmap_scanner.py src/netmap/cli.py tests/unit/test_nmap_timeouts.py
git commit -m "feat(scanner): thread default/deep host-timeout from config through NmapScanner"
```

---

## Phase 2 — Server core (Tasks 7-14)

These tasks build the in-process plumbing the web layer sits on top of: the privilege gate that prevents `netmap up` from binding without enough OS permission, the subnet bootstrap that auto-detects the local CIDR, the async event bus, the scan loop coroutine, the response DTOs, and the FastAPI app + lifespan.

### Task 7 — `server/privilege.py` — startup gate

**Files:**
- Create: `src/netmap/server/privilege.py`
- Create: `tests/unit/test_privilege.py`

This module is the **only** thing that runs before the server binds. It checks: (1) effective UID is 0, or the process has `CAP_NET_RAW + CAP_NET_ADMIN`; (2) the `nmap` binary is on PATH; (3) the configured bind is `127.0.0.1` (M2 refuses non-loopback). On any failure it prints a human-readable instruction to stderr and exits 1.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_privilege.py`:
```python
"""Privilege + nmap-binary + bind checks that gate `netmap up` startup."""
from __future__ import annotations

import pytest

from netmap.config import Config, ServerCfg
from netmap.server import privilege


def _cfg(bind: str = "127.0.0.1") -> Config:
    return Config(server=ServerCfg(bind=bind))


def test_check_or_exit_passes_when_root_and_nmap_present_and_bind_loopback(monkeypatch):
    monkeypatch.setattr(privilege, "_get_euid", lambda: 0)
    monkeypatch.setattr(privilege, "_which_nmap", lambda: "/usr/bin/nmap")
    privilege.check_or_exit(_cfg())  # must not raise / exit


def test_check_or_exit_passes_with_caps_when_not_root(monkeypatch):
    monkeypatch.setattr(privilege, "_get_euid", lambda: 1000)
    monkeypatch.setattr(privilege, "_has_net_caps", lambda: True)
    monkeypatch.setattr(privilege, "_which_nmap", lambda: "/usr/bin/nmap")
    privilege.check_or_exit(_cfg())


def test_check_or_exit_fails_without_root_or_caps(monkeypatch, capsys):
    monkeypatch.setattr(privilege, "_get_euid", lambda: 1000)
    monkeypatch.setattr(privilege, "_has_net_caps", lambda: False)
    monkeypatch.setattr(privilege, "_which_nmap", lambda: "/usr/bin/nmap")
    with pytest.raises(SystemExit) as exc:
        privilege.check_or_exit(_cfg())
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "raw-socket privileges" in err
    assert "sudo netmap up" in err


def test_check_or_exit_fails_when_nmap_missing(monkeypatch, capsys):
    monkeypatch.setattr(privilege, "_get_euid", lambda: 0)
    monkeypatch.setattr(privilege, "_which_nmap", lambda: None)
    with pytest.raises(SystemExit) as exc:
        privilege.check_or_exit(_cfg())
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "nmap binary not found" in err


def test_check_or_exit_fails_with_non_loopback_bind(monkeypatch, capsys):
    monkeypatch.setattr(privilege, "_get_euid", lambda: 0)
    monkeypatch.setattr(privilege, "_which_nmap", lambda: "/usr/bin/nmap")
    with pytest.raises(SystemExit) as exc:
        privilege.check_or_exit(_cfg(bind="0.0.0.0"))
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "non-loopback bind" in err and "M3" in err


def test_has_net_caps_parses_proc_status_capeff_bits(tmp_path, monkeypatch):
    # CapEff line containing CAP_NET_RAW (bit 13 = 0x2000) + CAP_NET_ADMIN (bit 12 = 0x1000)
    proc = tmp_path / "status"
    proc.write_text("Name:\tpython\nCapEff:\t0000000000003000\n")
    monkeypatch.setattr(privilege, "_PROC_SELF_STATUS", str(proc))
    assert privilege._has_net_caps() is True

    proc.write_text("Name:\tpython\nCapEff:\t0000000000000000\n")
    assert privilege._has_net_caps() is False
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/unit/test_privilege.py -v`
Expected: ImportError / module not found — `netmap.server.privilege` does not exist.

- [ ] **Step 3: Implement `server/privilege.py`**

`src/netmap/server/privilege.py`:
```python
"""Startup checks for `netmap up`. Runs before the server binds.

Three gates: (1) root or CAP_NET_RAW+CAP_NET_ADMIN, (2) nmap on PATH,
(3) bind == 127.0.0.1 (M2 only; auth lands in M3).
"""
from __future__ import annotations

import os
import shutil
import sys

from netmap.config import Config

_PROC_SELF_STATUS = "/proc/self/status"
_CAP_NET_ADMIN = 1 << 12
_CAP_NET_RAW = 1 << 13


_NOT_PRIVILEGED = """\
net-map needs raw-socket privileges. Either:
  sudo netmap up
or grant once:
  sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
"""

_NO_NMAP = """\
nmap binary not found on PATH. Install it:
  Debian/Ubuntu:  sudo apt install nmap
  Arch:           sudo pacman -S nmap
  macOS:          brew install nmap
"""

_NON_LOOPBACK = """\
non-loopback bind requires bearer-token auth, which lands in M3.
Set [server].bind = "127.0.0.1" or wait for M3.
"""


def _get_euid() -> int:
    return os.geteuid()


def _which_nmap() -> str | None:
    return shutil.which("nmap")


def _has_net_caps() -> bool:
    try:
        with open(_PROC_SELF_STATUS) as f:
            for line in f:
                if line.startswith("CapEff:"):
                    bits = int(line.split()[1], 16)
                    return bool(bits & _CAP_NET_RAW) and bool(bits & _CAP_NET_ADMIN)
    except OSError:
        return False
    return False


def check_or_exit(cfg: Config) -> None:
    """Run all startup checks; exit 1 with stderr instruction on any failure."""
    if _get_euid() != 0 and not _has_net_caps():
        print(_NOT_PRIVILEGED, file=sys.stderr, end="")
        sys.exit(1)

    if _which_nmap() is None:
        print(_NO_NMAP, file=sys.stderr, end="")
        sys.exit(1)

    if cfg.server.bind != "127.0.0.1":
        print(_NON_LOOPBACK, file=sys.stderr, end="")
        sys.exit(1)
```

- [ ] **Step 4: Re-run the tests**

Run: `uv run pytest tests/unit/test_privilege.py -v`
Expected: all six tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/server/privilege.py tests/unit/test_privilege.py
git commit -m "feat(server): add privilege.check_or_exit() startup gate"
```

---

### Task 8 — `server/subnet_bootstrap.py` — `parse_ip_route` pure parser

**Files:**
- Create: `src/netmap/server/subnet_bootstrap.py`
- Create: `tests/unit/test_subnet_bootstrap.py`

The auto-detect path runs two `ip` subcommands and parses the text. Step 1 isolates the parsing into a pure function over the captured text — easy to unit-test against fixture strings.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_subnet_bootstrap.py`:
```python
"""Subnet auto-detect — parse `ip route` text and infer the host's primary CIDR."""
from __future__ import annotations

from netmap.server.subnet_bootstrap import parse_ip_route, parse_iface_cidr

ROUTE_LINUX = """\
default via 192.168.1.1 dev wlan0 proto dhcp metric 600
192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.42 metric 600
"""

ADDR_LINUX = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: wlan0    inet 192.168.1.42/24 brd 192.168.1.255 scope global dynamic noprefixroute wlan0\\       valid_lft 3500sec preferred_lft 3500sec
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever
"""


def test_parse_ip_route_extracts_default_iface():
    assert parse_ip_route(ROUTE_LINUX) == "wlan0"


def test_parse_ip_route_returns_none_when_no_default():
    assert parse_ip_route("192.168.1.0/24 dev wlan0 proto kernel scope link\n") is None


def test_parse_ip_route_returns_none_on_garbage():
    assert parse_ip_route("xyzzy\n") is None


def test_parse_iface_cidr_finds_matching_interface():
    assert parse_iface_cidr(ADDR_LINUX, "wlan0") == "192.168.1.0/24"


def test_parse_iface_cidr_returns_none_when_iface_absent():
    assert parse_iface_cidr(ADDR_LINUX, "eth7") is None


def test_parse_iface_cidr_skips_lo_when_searching_for_other_iface():
    # The function must not return 127.0.0.0/8 when asked for wlan0
    assert parse_iface_cidr(ADDR_LINUX, "wlan0") != "127.0.0.0/8"
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/unit/test_subnet_bootstrap.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement the parsers**

`src/netmap/server/subnet_bootstrap.py`:
```python
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

    db.insert_subnet(Subnet(
        cidr=detected, source="config", enabled=True,
        hop_distance=0, first_seen=now,
    ))
    logger.info("auto-detected subnet: %s", detected)
```

- [ ] **Step 4: Re-run the parser tests**

Run: `uv run pytest tests/unit/test_subnet_bootstrap.py -v -k "parse_"`
Expected: all six parser tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/server/subnet_bootstrap.py tests/unit/test_subnet_bootstrap.py
git commit -m "feat(server): add subnet_bootstrap parsers + run() integrator"
```

---

### Task 9 — Subnet bootstrap: integration tests for `run()`

**Files:**
- Modify: `tests/unit/test_subnet_bootstrap.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_subnet_bootstrap.py`:

```python
from datetime import UTC, datetime
from netmap.models import Subnet
from netmap.server import subnet_bootstrap
from netmap.storage import Storage


def test_run_with_override_inserts_user_cidr():
    db = Storage(":memory:")

    subnet_bootstrap.run(db, override=["10.5.0.0/24"])

    rows = db.list_subnets()
    assert [s.cidr for s in rows] == ["10.5.0.0/24"]
    assert rows[0].source == "config"
    assert rows[0].enabled is True


def test_run_with_override_skips_invalid_cidrs(caplog):
    db = Storage(":memory:")

    with caplog.at_level("WARNING", logger="netmap.bootstrap"):
        subnet_bootstrap.run(db, override=["10.5.0.0/24", "0.0.0.0/8"])

    assert [s.cidr for s in db.list_subnets()] == ["10.5.0.0/24"]
    assert any("rejected" in rec.message for rec in caplog.records)


def test_run_no_op_when_subnets_already_present(monkeypatch):
    db = Storage(":memory:")
    db.insert_subnet(Subnet(
        cidr="192.168.1.0/24", source="config", enabled=True,
        hop_distance=0, first_seen=datetime.now(tz=UTC),
    ))

    called = {"n": 0}
    def fake_detect():
        called["n"] += 1
        return "10.0.0.0/24"
    monkeypatch.setattr(subnet_bootstrap, "_detect_local_cidr", fake_detect)

    subnet_bootstrap.run(db, override=None)

    assert called["n"] == 0
    assert [s.cidr for s in db.list_subnets()] == ["192.168.1.0/24"]


def test_run_auto_detects_when_table_empty(monkeypatch):
    db = Storage(":memory:")
    monkeypatch.setattr(
        subnet_bootstrap, "_detect_local_cidr", lambda: "192.168.7.0/24"
    )

    subnet_bootstrap.run(db, override=None)

    assert [s.cidr for s in db.list_subnets()] == ["192.168.7.0/24"]


def test_run_logs_warning_when_detection_fails(monkeypatch, caplog):
    db = Storage(":memory:")
    monkeypatch.setattr(subnet_bootstrap, "_detect_local_cidr", lambda: None)

    with caplog.at_level("WARNING", logger="netmap.bootstrap"):
        subnet_bootstrap.run(db, override=None)

    assert db.list_subnets() == []
    assert any("auto-detect failed" in rec.message for rec in caplog.records)
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/unit/test_subnet_bootstrap.py -v`
Expected: the five new tests PASS (the implementation in Task 8 already covers all paths).

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_subnet_bootstrap.py
git commit -m "test(server): cover subnet_bootstrap.run() override/no-op/auto-detect/failure paths"
```

---

### Task 10 — `server/events.py` — AsyncBus

**Files:**
- Create: `src/netmap/server/events.py`
- Create: `tests/unit/test_events_bus.py`

In-process fan-out: one publisher (the scan loop + `correlate`'s wrapper), many subscribers (each SSE connection). Slow consumers must not block the publisher — drop the oldest queued event instead.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_events_bus.py`:
```python
"""AsyncBus fan-out, slow-consumer drop-oldest, subscribe/unsubscribe lifecycle."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from netmap.models import Event
from netmap.server.events import AsyncBus


def _ev(kind: str, payload: dict | None = None) -> Event:
    return Event(ts=datetime.now(tz=UTC), kind=kind, payload=payload)


@pytest.mark.asyncio
async def test_single_subscriber_receives_published_event():
    bus = AsyncBus()
    q = bus.subscribe()

    await bus.publish(_ev("host.new", {"id": 1}))

    got = await asyncio.wait_for(q.get(), timeout=1)
    assert got.kind == "host.new"
    assert got.payload == {"id": 1}


@pytest.mark.asyncio
async def test_multiple_subscribers_each_get_a_copy():
    bus = AsyncBus()
    q1, q2 = bus.subscribe(), bus.subscribe()

    await bus.publish(_ev("port.opened"))

    e1 = await asyncio.wait_for(q1.get(), timeout=1)
    e2 = await asyncio.wait_for(q2.get(), timeout=1)
    assert e1.kind == "port.opened"
    assert e2.kind == "port.opened"


@pytest.mark.asyncio
async def test_unsubscribe_stops_delivery():
    bus = AsyncBus()
    q = bus.subscribe()
    bus.unsubscribe(q)

    await bus.publish(_ev("ip.changed"))

    assert q.empty()


@pytest.mark.asyncio
async def test_slow_consumer_drops_oldest_when_queue_full():
    bus = AsyncBus(queue_size=3)
    q = bus.subscribe()

    for i in range(5):
        await bus.publish(_ev("scan.ok", {"i": i}))

    # The queue holds at most 3 — and after drop-oldest the surviving events
    # should be the most recent three (i=2, 3, 4).
    survivors = []
    while not q.empty():
        survivors.append(q.get_nowait().payload["i"])
    assert survivors == [2, 3, 4]


@pytest.mark.asyncio
async def test_publish_does_not_block_when_no_subscribers():
    bus = AsyncBus()
    await bus.publish(_ev("scan.started"))  # must not raise / hang
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/unit/test_events_bus.py -v`
Expected: ImportError — `netmap.server.events` doesn't exist.

- [ ] **Step 3: Implement `AsyncBus`**

`src/netmap/server/events.py`:
```python
"""In-process event broadcaster used by SSE and the scan loop.

One queue per subscriber. Slow consumers drop the oldest event instead of
blocking the publisher. The catch-up path (refetch /events?since=<ts>) is
the client's responsibility.
"""
from __future__ import annotations

import asyncio

from netmap.models import Event


class AsyncBus:
    def __init__(self, queue_size: int = 200) -> None:
        self._queue_size = queue_size
        self._subscribers: set[asyncio.Queue[Event]] = set()

    def subscribe(self) -> asyncio.Queue[Event]:
        q: asyncio.Queue[Event] = asyncio.Queue(maxsize=self._queue_size)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[Event]) -> None:
        self._subscribers.discard(q)

    async def publish(self, event: Event) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    pass
```

- [ ] **Step 4: Re-run the tests**

Run: `uv run pytest tests/unit/test_events_bus.py -v`
Expected: all five tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/server/events.py tests/unit/test_events_bus.py
git commit -m "feat(server): add AsyncBus event broadcaster with drop-oldest semantics"
```

---

### Task 11 — `scanner/loop.py` — `maybe_run` dispatcher

**Files:**
- Modify: `src/netmap/scanner/loop.py`
- Create: `tests/unit/test_loop.py`

`maybe_run` is the single funnel every scan flows through — both the loop's discover/default ticks and the API's `POST /scans`. It validates against the in-flight set, opens a `scan` row, publishes `scan.started`, then spawns the real work as a background task and returns the scan_id immediately. The background task runs the scanners → correlate → publishes per-event signals → finishes the scan row with `ok` / `error` → cleans up `in_flight`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_loop.py`:
```python
"""scan_loop and maybe_run — dispatching, in-flight guard, error containment."""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from ipaddress import IPv4Network
from typing import ClassVar

import pytest

from netmap.config import Config
from netmap.models import Fact, HostKey, MacFact, Subnet
from netmap.scanner.base import ScanMode
from netmap.scanner.loop import maybe_run
from netmap.server.events import AsyncBus
from netmap.storage import Storage


class FakeScanner:
    name: ClassVar[str] = "test.fake"
    def __init__(self, facts: list[Fact], raises: Exception | None = None) -> None:
        self._facts = facts
        self._raises = raises
    async def scan(self, target: IPv4Network, mode: ScanMode) -> AsyncIterator[Fact]:
        if self._raises:
            raise self._raises
        for f in self._facts:
            yield f


def _seed_subnet(db: Storage, cidr: str = "192.168.1.0/24") -> None:
    db.insert_subnet(Subnet(
        cidr=cidr, source="config", enabled=True,
        hop_distance=0, first_seen=datetime.now(tz=UTC),
    ))


async def _collect_events(bus: AsyncBus, expected: int, timeout: float = 2) -> list:
    q = bus.subscribe()
    out = []
    async with asyncio.timeout(timeout):
        while len(out) < expected:
            out.append(await q.get())
    return out


@pytest.mark.asyncio
async def test_maybe_run_opens_scan_row_and_dispatches_work():
    db = Storage(":memory:")
    _seed_subnet(db)
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    fact = MacFact(mac="aa:bb:cc:dd:ee:01", ip="192.168.1.10", src="test.fake")

    sub = bus.subscribe()
    scan_id = await maybe_run(
        mode=ScanMode.DISCOVER,
        targets=[IPv4Network("192.168.1.0/24")],
        db=db, bus=bus, cfg=Config(), in_flight=in_flight,
        source="test",
        scanners_for_mode=lambda _cfg, _mode: [FakeScanner([fact])],
    )
    assert scan_id is not None
    started = await asyncio.wait_for(sub.get(), timeout=1)
    assert started.kind == "scan.started"
    # Let the background task finish
    await asyncio.sleep(0.05)
    saw = []
    while not sub.empty():
        saw.append(sub.get_nowait().kind)
    assert "scan.ok" in saw


@pytest.mark.asyncio
async def test_maybe_run_skips_when_same_target_in_flight():
    db = Storage(":memory:")
    bus = AsyncBus()
    in_flight = {(ScanMode.DISCOVER.value, "192.168.1.0/24")}

    sub = bus.subscribe()
    scan_id = await maybe_run(
        mode=ScanMode.DISCOVER,
        targets=[IPv4Network("192.168.1.0/24")],
        db=db, bus=bus, cfg=Config(), in_flight=in_flight,
        source="test",
        scanners_for_mode=lambda _c, _m: [],
    )
    assert scan_id is None
    skipped = await asyncio.wait_for(sub.get(), timeout=1)
    assert skipped.kind == "scan.skipped"


@pytest.mark.asyncio
async def test_maybe_run_catches_scanner_exception_and_publishes_scan_error():
    db = Storage(":memory:")
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()

    sub = bus.subscribe()
    scan_id = await maybe_run(
        mode=ScanMode.DISCOVER,
        targets=[IPv4Network("192.168.1.0/24")],
        db=db, bus=bus, cfg=Config(), in_flight=in_flight,
        source="test",
        scanners_for_mode=lambda _c, _m: [FakeScanner([], raises=RuntimeError("boom"))],
    )
    assert scan_id is not None

    await asyncio.sleep(0.1)
    kinds: list[str] = []
    while not sub.empty():
        kinds.append(sub.get_nowait().kind)
    assert "scan.error" in kinds

    scan = db.get_scan(scan_id)
    assert scan.status == "error"

    # in_flight set must be cleared so a follow-up can run
    assert in_flight == set()


@pytest.mark.asyncio
async def test_maybe_run_finishes_scan_with_ok_status_on_happy_path():
    db = Storage(":memory:")
    _seed_subnet(db)
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    fact = MacFact(mac="aa:bb:cc:dd:ee:01", ip="192.168.1.10", src="test.fake")

    scan_id = await maybe_run(
        mode=ScanMode.DEFAULT,
        targets=[IPv4Network("192.168.1.0/24")],
        db=db, bus=bus, cfg=Config(), in_flight=in_flight,
        source="test",
        scanners_for_mode=lambda _c, _m: [FakeScanner([fact])],
    )
    assert scan_id is not None
    await asyncio.sleep(0.1)
    assert db.get_scan(scan_id).status == "ok"
    assert in_flight == set()
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/unit/test_loop.py -v`
Expected: FAIL — `maybe_run` does not exist.

- [ ] **Step 3: Implement `maybe_run` + helpers**

Replace the contents of `src/netmap/scanner/loop.py` with:

```python
"""Foreground asyncio scan loop + per-scan dispatcher.

`scan_loop` runs while the process is alive and ticks on `cfg.scan.interval_s`.
`maybe_run` opens a scan row, registers the (mode, target_signature) pair in
the shared in-flight set, and dispatches the actual scan work as a background
task. Both the periodic loop and the API's `POST /scans` go through this
single funnel.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import IPv4Network

from netmap.config import Config
from netmap.correlation import correlate
from netmap.models import Event, Fact, Scan
from netmap.scanner.arp_scanner import ArpScanner
from netmap.scanner.base import ActiveScanner, ScanMode
from netmap.scanner.nmap_scanner import NmapScanner
from netmap.server.events import AsyncBus
from netmap.storage import Storage

logger = logging.getLogger("netmap.loop")

ScannerFactory = Callable[[Config, ScanMode], list[ActiveScanner]]


def default_scanners(cfg: Config, mode: ScanMode) -> list[ActiveScanner]:
    """Real scanner stack: nmap + scapy ARP. ARP is link-local only;
    nmap discover sweep handles everything past the local subnet."""
    return [
        NmapScanner(
            default_host_timeout=cfg.scan.default_scan_host_timeout,
            deep_host_timeout=cfg.scan.deep_scan_host_timeout,
        ),
        ArpScanner(iface=None),
    ]


def _signature(targets: list[IPv4Network]) -> str:
    return ",".join(sorted(str(t) for t in targets))


async def maybe_run(
    *,
    mode: ScanMode,
    targets: list[IPv4Network],
    db: Storage,
    bus: AsyncBus,
    cfg: Config,
    in_flight: set[tuple[str, str]],
    source: str,
    scanners_for_mode: ScannerFactory = default_scanners,
) -> int | None:
    """Open a scan row, dispatch the work as a background task, return scan_id.

    Returns None if (mode, target_signature) is already in flight — in which
    case a `scan.skipped` event is published and a status='skipped' scan row
    is written for the audit trail.
    """
    now = datetime.now(tz=UTC)
    sig = _signature(targets)
    key = (mode.value, sig)

    if key in in_flight:
        scan_id = db.start_scan(Scan(
            started_at=now, source=source, target=sig, mode=mode.value,
            status="skipped", hosts_seen=0,
            notes="another scan with the same target/mode is already running",
        ))
        db.finish_scan(scan_id, ended_at=now, status="skipped", hosts_seen=0)
        await bus.publish(Event(
            ts=now, scan_id=scan_id, kind="scan.skipped",
            payload={"reason": "already running", "mode": mode.value, "target": sig},
        ))
        return None

    in_flight.add(key)
    scan_id = db.start_scan(Scan(
        started_at=now, source=source, target=sig, mode=mode.value,
        status="running", hosts_seen=0,
    ))
    await bus.publish(Event(
        ts=now, scan_id=scan_id, kind="scan.started",
        payload={"mode": mode.value, "target": sig},
    ))

    asyncio.create_task(_run_scan_work(
        mode=mode, targets=targets, scan_id=scan_id,
        db=db, bus=bus, cfg=cfg, in_flight=in_flight, key=key,
        scanners=scanners_for_mode(cfg, mode),
    ))
    return scan_id


async def _run_scan_work(
    *,
    mode: ScanMode,
    targets: list[IPv4Network],
    scan_id: int,
    db: Storage,
    bus: AsyncBus,
    cfg: Config,
    in_flight: set[tuple[str, str]],
    key: tuple[str, str],
    scanners: list[ActiveScanner],
) -> None:
    started = time.monotonic()
    try:
        facts: list[Fact] = []
        for target in targets:
            for scanner in scanners:
                async for fact in scanner.scan(target, mode):
                    facts.append(fact)
        now = datetime.now(tz=UTC)
        observed = (
            [str(t) for t in targets]
            if mode in (ScanMode.DEFAULT, ScanMode.DEEP)
            else []
        )
        events = correlate(
            facts, db, scan_id, now=now, observed_subnets=observed,
        )
        for ev in events:
            await bus.publish(ev)

        hosts = db._conn.execute("SELECT COUNT(*) FROM host").fetchone()[0]
        db.finish_scan(
            scan_id, ended_at=now, status="ok", hosts_seen=int(hosts),
        )
        await bus.publish(Event(
            ts=now, scan_id=scan_id, kind="scan.ok",
            payload={"hosts_seen": int(hosts),
                     "duration_s": round(time.monotonic() - started, 3)},
        ))
    except Exception as exc:
        now = datetime.now(tz=UTC)
        logger.exception("scan %s failed", scan_id)
        db.finish_scan(scan_id, ended_at=now, status="error", hosts_seen=0)
        await bus.publish(Event(
            ts=now, scan_id=scan_id, kind="scan.error",
            payload={"error": str(exc), "mode": mode.value,
                     "target": _signature(targets)},
        ))
    finally:
        in_flight.discard(key)
```

- [ ] **Step 4: Re-run the tests**

Run: `uv run pytest tests/unit/test_loop.py -v`
Expected: all four tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/scanner/loop.py tests/unit/test_loop.py
git commit -m "feat(scanner): add loop.maybe_run() dispatcher with in-flight guard + error containment"
```

---

### Task 12 — `scanner/loop.py` — `scan_loop` cadence coroutine

**Files:**
- Modify: `src/netmap/scanner/loop.py`
- Modify: `tests/unit/test_loop.py`

The actual periodic loop wraps `maybe_run`. Discover ticks every `cfg.scan.interval_s` (default 60 s). A default scan kicks off every `cfg.scan.default_scan_interval_s` (default 600 s) — dispatched but not awaited, so it doesn't block the next discover tick. The loop exits cleanly when `stop.set()` is called.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_loop.py`:

```python
from netmap.config import ScanCfg
from netmap.scanner.loop import scan_loop


@pytest.mark.asyncio
async def test_scan_loop_dispatches_discover_each_tick_until_stop_is_set(monkeypatch):
    db = Storage(":memory:")
    _seed_subnet(db)
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    stop = asyncio.Event()

    cfg = Config(scan=ScanCfg(interval_s=1, default_scan_interval_s=99_999))

    calls: list[ScanMode] = []
    async def fake_maybe_run(*, mode, **_):
        calls.append(mode)
        return 1
    monkeypatch.setattr("netmap.scanner.loop.maybe_run", fake_maybe_run)

    task = asyncio.create_task(scan_loop(db, bus, stop, cfg, in_flight))
    await asyncio.sleep(2.2)
    stop.set()
    await asyncio.wait_for(task, timeout=2)

    assert calls.count(ScanMode.DISCOVER) >= 2


@pytest.mark.asyncio
async def test_scan_loop_dispatches_default_after_interval(monkeypatch):
    db = Storage(":memory:")
    _seed_subnet(db)
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    stop = asyncio.Event()

    # discover every 1s; default every 2s
    cfg = Config(scan=ScanCfg(interval_s=1, default_scan_interval_s=2))

    calls: list[ScanMode] = []
    async def fake_maybe_run(*, mode, **_):
        calls.append(mode)
        return 1
    monkeypatch.setattr("netmap.scanner.loop.maybe_run", fake_maybe_run)

    task = asyncio.create_task(scan_loop(db, bus, stop, cfg, in_flight))
    await asyncio.sleep(2.5)
    stop.set()
    await asyncio.wait_for(task, timeout=2)

    assert ScanMode.DEFAULT in calls


@pytest.mark.asyncio
async def test_scan_loop_exits_promptly_on_stop():
    db = Storage(":memory:")
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    stop = asyncio.Event()
    cfg = Config(scan=ScanCfg(interval_s=60, default_scan_interval_s=600))

    task = asyncio.create_task(scan_loop(db, bus, stop, cfg, in_flight))
    await asyncio.sleep(0.1)
    stop.set()
    await asyncio.wait_for(task, timeout=2)
    # task should return without exception
    assert task.done() and task.exception() is None
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/unit/test_loop.py -v -k "scan_loop"`
Expected: FAIL — `scan_loop` does not exist.

- [ ] **Step 3: Append `scan_loop` to `src/netmap/scanner/loop.py`**

Append to the end of `src/netmap/scanner/loop.py`:

```python
async def scan_loop(
    db: Storage,
    bus: AsyncBus,
    stop: asyncio.Event,
    cfg: Config,
    in_flight: set[tuple[str, str]],
) -> None:
    """Tick `discover` every `cfg.scan.interval_s` and `default` every
    `cfg.scan.default_scan_interval_s`. Exits when `stop` is set."""
    last_default = 0.0
    while not stop.is_set():
        subnets = [s for s in db.list_subnets() if s.enabled]
        targets: list[IPv4Network] = []
        for s in subnets:
            try:
                targets.append(IPv4Network(s.cidr))
            except (ValueError, TypeError):
                logger.warning("skipping unparseable subnet cidr: %s", s.cidr)

        if targets:
            await maybe_run(
                mode=ScanMode.DISCOVER, targets=targets,
                db=db, bus=bus, cfg=cfg, in_flight=in_flight,
                source="loop.discover",
            )
            if time.monotonic() - last_default > cfg.scan.default_scan_interval_s:
                asyncio.create_task(maybe_run(
                    mode=ScanMode.DEFAULT, targets=targets,
                    db=db, bus=bus, cfg=cfg, in_flight=in_flight,
                    source="loop.default",
                ))
                last_default = time.monotonic()

        try:
            await asyncio.wait_for(stop.wait(), timeout=cfg.scan.interval_s)
        except asyncio.TimeoutError:
            pass
```

- [ ] **Step 4: Re-run the tests**

Run: `uv run pytest tests/unit/test_loop.py -v`
Expected: all seven loop tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/scanner/loop.py tests/unit/test_loop.py
git commit -m "feat(scanner): add scan_loop() cadence coroutine over maybe_run()"
```

---

### Task 13 — `server/schemas.py` — response DTOs

**Files:**
- Create: `src/netmap/server/schemas.py`
- Create: `tests/api/test_schemas.py`

- [ ] **Step 1: Write the failing tests**

`tests/api/test_schemas.py`:
```python
"""Schema roundtrips — model_validate + model_dump for response DTOs."""
from __future__ import annotations

from datetime import UTC, datetime

from netmap.scanner.base import ScanMode
from netmap.server.schemas import (
    HostIp, HostSummary, ScanRequest, ScanResponse,
)


def test_host_summary_roundtrip():
    payload = {
        "id": 1, "mac": "aa:bb:cc:dd:ee:01", "primary_ip": "192.168.1.10",
        "hostname": "printer", "vendor": "Brother", "device_type": "printer",
        "trusted": False, "open_port_count": 2,
        "last_seen": datetime.now(tz=UTC),
    }
    hs = HostSummary(**payload)
    assert hs.model_dump()["primary_ip"] == "192.168.1.10"


def test_host_ip_requires_ip_and_timestamps():
    ip = HostIp(ip="192.168.1.10",
                first_seen=datetime.now(tz=UTC),
                last_seen=datetime.now(tz=UTC))
    assert ip.ip == "192.168.1.10"


def test_scan_request_defaults():
    req = ScanRequest(mode=ScanMode.DISCOVER)
    assert req.targets is None
    assert req.confirm is False


def test_scan_response_shape():
    resp = ScanResponse(scan_id=42, accepted_targets=["192.168.1.0/24"])
    assert resp.model_dump() == {"scan_id": 42, "accepted_targets": ["192.168.1.0/24"]}
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/api/test_schemas.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement the schemas**

`src/netmap/server/schemas.py`:
```python
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
```

- [ ] **Step 4: Re-run the tests**

Run: `uv run pytest tests/api/test_schemas.py -v`
Expected: all four tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/server/schemas.py tests/api/test_schemas.py
git commit -m "feat(server): add response DTOs (HostSummary, HostDetail, ScanRequest, ScanResponse)"
```

---

### Task 14 — `server/app.py` — `create_app` + lifespan

**Files:**
- Create: `src/netmap/server/app.py`
- Create: `tests/api/conftest.py`
- Create: `tests/api/test_lifespan.py`

`create_app` builds the FastAPI instance with everything stashed on `app.state` so route handlers can grab it. The lifespan kicks off the scan-loop task on startup and stops it cleanly on shutdown. `run()` is the high-level entry the CLI calls.

- [ ] **Step 1: Write the failing tests**

`tests/api/conftest.py`:
```python
"""Shared fixtures for API tests.

The `client` fixture builds a FastAPI app wired to an in-memory Storage and
a fresh AsyncBus, with the scan loop scanner factory replaced by a no-op so
real subprocess calls never happen.
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from netmap.config import Config, ScanCfg
from netmap.scanner.base import ScanMode
from netmap.server.app import create_app
from netmap.server.events import AsyncBus
from netmap.storage import Storage


@pytest.fixture
def storage() -> Storage:
    return Storage(":memory:")


@pytest.fixture
def bus() -> AsyncBus:
    return AsyncBus()


@pytest.fixture
def in_flight() -> set[tuple[str, str]]:
    return set()


@pytest.fixture
def cfg() -> Config:
    # Long intervals so the loop doesn't fire during a test.
    return Config(scan=ScanCfg(interval_s=99_999, default_scan_interval_s=99_999))


@pytest.fixture
def client(cfg, storage, bus, in_flight):
    stop = asyncio.Event()
    app = create_app(
        cfg=cfg, db=storage, bus=bus, in_flight=in_flight, stop=stop,
    )
    with TestClient(app) as c:
        yield c
```

`tests/api/test_lifespan.py`:
```python
"""Lifespan starts the scan loop on startup and stops it on shutdown."""
from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from netmap.config import Config, ScanCfg
from netmap.server.app import create_app
from netmap.server.events import AsyncBus
from netmap.storage import Storage


def test_lifespan_starts_and_stops_scan_loop():
    db = Storage(":memory:")
    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    stop = asyncio.Event()
    cfg = Config(scan=ScanCfg(interval_s=99_999, default_scan_interval_s=99_999))

    app = create_app(cfg=cfg, db=db, bus=bus, in_flight=in_flight, stop=stop)
    with TestClient(app) as _c:
        # Inside the `with`, the lifespan has run startup.
        # The scan loop task must exist and be running.
        loop_task = app.state.netmap_loop_task
        assert loop_task is not None
        assert not loop_task.done()

    # On exit, lifespan shutdown ran — stop was set and the task is done.
    assert stop.is_set()
    assert loop_task.done()
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/api/test_lifespan.py -v`
Expected: ImportError — `netmap.server.app.create_app` does not exist.

- [ ] **Step 3: Implement `create_app`**

`src/netmap/server/app.py`:
```python
"""FastAPI app factory + lifespan + high-level `run()` entry.

`create_app` is the test-friendly seam: it takes all dependencies as keyword
args. `run()` is the production wiring used by `netmap up` — it builds the
real Storage / AsyncBus / etc, runs privilege/bootstrap, and hands off to
uvicorn.
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from netmap.config import Config
from netmap.scanner.loop import scan_loop
from netmap.server import privilege, subnet_bootstrap
from netmap.server.events import AsyncBus
from netmap.storage import Storage

logger = logging.getLogger("netmap.server")


def create_app(
    *,
    cfg: Config,
    db: Storage,
    bus: AsyncBus,
    in_flight: set[tuple[str, str]],
    stop: asyncio.Event,
) -> FastAPI:
    """Build a FastAPI app. The lifespan owns the scan-loop task."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        loop_task = asyncio.create_task(
            scan_loop(db, bus, stop, cfg, in_flight),
            name="netmap.scan_loop",
        )
        app.state.netmap_loop_task = loop_task
        try:
            yield
        finally:
            stop.set()
            try:
                await asyncio.wait_for(loop_task, timeout=3)
            except asyncio.TimeoutError:
                logger.warning("scan loop did not stop within 3s; cancelling")
                loop_task.cancel()

    app = FastAPI(
        title="net-map",
        version="0.2.0",
        lifespan=lifespan,
    )
    app.state.cfg = cfg
    app.state.db = db
    app.state.bus = bus
    app.state.in_flight = in_flight
    # Routes registered in Tasks 15-19 will be added below this comment.
    return app


def run(
    cfg: Config,
    *,
    db_path: Path,
    cli_targets: list[str] | None = None,
) -> None:
    """Production entry. Runs privilege checks + bootstrap, then hands off to uvicorn."""
    import uvicorn

    privilege.check_or_exit(cfg)

    db = Storage(str(db_path))
    subnet_bootstrap.run(db, override=cli_targets)

    bus = AsyncBus()
    in_flight: set[tuple[str, str]] = set()
    stop = asyncio.Event()
    app = create_app(cfg=cfg, db=db, bus=bus, in_flight=in_flight, stop=stop)

    uvicorn.run(
        app,
        host=cfg.server.bind,
        port=cfg.server.port,
        log_level="info",
    )
```

- [ ] **Step 4: Re-run the tests**

Run: `uv run pytest tests/api/test_lifespan.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/server/app.py tests/api/conftest.py tests/api/test_lifespan.py
git commit -m "feat(server): add create_app() + lifespan + run() entry"
```

---

## Phase 3 — REST API (Tasks 15-19)

Each task adds a slice of routes, registered into the FastAPI app via a single `routes.register(app)` call appended to `create_app` at the end of Phase 3.

### Task 15 — `GET /api/v1/hosts` + `GET /api/v1/hosts/{id}`

**Files:**
- Create: `src/netmap/server/routes.py`
- Modify: `src/netmap/server/app.py` (call `routes.register(app)`)
- Create: `tests/api/test_hosts.py`

- [ ] **Step 1: Write the failing tests**

`tests/api/test_hosts.py`:
```python
"""GET /api/v1/hosts and /api/v1/hosts/{id}."""
from __future__ import annotations

from datetime import UTC, datetime

from netmap.models import Event, Host, Port, Subnet


def _now():
    return datetime.now(tz=UTC)


def _seed(storage):
    h1 = storage.upsert_host(Host(
        mac="aa:bb:cc:dd:ee:01", primary_ip="192.168.1.10",
        hostname="printer-lobby", vendor="Brother",
        first_seen=_now(), last_seen=_now(),
    ))
    h2 = storage.upsert_host(Host(
        mac="aa:bb:cc:dd:ee:02", primary_ip="192.168.1.11",
        hostname="laptop", vendor="Apple",
        first_seen=_now(), last_seen=_now(),
    ))
    storage.upsert_port(Port(
        host_id=h1.id, protocol="tcp", number=9100, state="open",
        first_seen=_now(), last_seen=_now(),
    ))
    storage.insert_subnet(Subnet(
        cidr="192.168.1.0/24", source="config", enabled=True,
        hop_distance=0, first_seen=_now(),
    ))
    storage.insert_event(Event(
        ts=_now(), host_id=h1.id, kind="host.new", payload={"ip": h1.primary_ip},
    ))
    return h1.id, h2.id


def test_get_hosts_returns_summary_with_open_port_count(client, storage):
    h1, h2 = _seed(storage)

    r = client.get("/api/v1/hosts")
    assert r.status_code == 200
    data = r.json()
    by_ip = {row["primary_ip"]: row for row in data}
    assert by_ip["192.168.1.10"]["open_port_count"] == 1
    assert by_ip["192.168.1.10"]["hostname"] == "printer-lobby"
    assert by_ip["192.168.1.11"]["open_port_count"] == 0


def test_get_hosts_filters_by_q(client, storage):
    _seed(storage)
    r = client.get("/api/v1/hosts?q=printer")
    assert r.status_code == 200
    rows = r.json()
    assert [row["primary_ip"] for row in rows] == ["192.168.1.10"]


def test_get_hosts_filters_by_subnet(client, storage):
    h1, _ = _seed(storage)
    sid = storage.get_subnet_by_cidr("192.168.1.0/24").id
    r = client.get(f"/api/v1/hosts?subnet={sid}")
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 2


def test_get_host_detail_returns_ports_history_events(client, storage):
    h1, _ = _seed(storage)
    r = client.get(f"/api/v1/hosts/{h1}")
    assert r.status_code == 200
    body = r.json()
    assert body["host"]["primary_ip"] == "192.168.1.10"
    assert len(body["open_ports"]) == 1
    assert body["open_ports"][0]["number"] == 9100
    assert any(ev["kind"] == "host.new" for ev in body["recent_events"])
    assert body["edges"] == []


def test_get_host_detail_404_on_unknown_id(client):
    r = client.get("/api/v1/hosts/9999")
    assert r.status_code == 404
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/api/test_hosts.py -v`
Expected: FAIL — routes not yet registered.

- [ ] **Step 3: Implement `routes.py` and the host endpoints**

`src/netmap/server/routes.py`:
```python
"""REST endpoints for net-map M2.

All routes hang off `/api/v1`. Static UI mounting + GET / live here too.
Handlers pull dependencies (Config, Storage, AsyncBus, in_flight) off
`request.app.state`, so the same router works against the production app
and the test app without DI plumbing.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request

from netmap.server.schemas import HostDetail, HostIp, HostSummary

api = APIRouter(prefix="/api/v1")


def _state(request: Request):
    return request.app.state


@api.get("/hosts", response_model=list[HostSummary])
def get_hosts(
    request: Request,
    subnet: int | None = Query(default=None),
    q: str | None = Query(default=None),
):
    rows = _state(request).db.list_host_summaries(subnet_id=subnet, q=q)
    return [
        HostSummary(
            id=r["id"], mac=r["mac"], primary_ip=r["primary_ip"],
            hostname=r["hostname"], vendor=r["vendor"],
            device_type=r["device_type"], trusted=r["trusted"],
            open_port_count=r["open_port_count"],
            last_seen=datetime.fromisoformat(r["last_seen"]),
        )
        for r in rows
    ]


@api.get("/hosts/{host_id}", response_model=HostDetail)
def get_host(request: Request, host_id: int):
    db = _state(request).db
    host = db.get_host(host_id)
    if host is None:
        raise HTTPException(status_code=404, detail=f"host {host_id} not found")
    open_ports = db.list_ports(host_id, only_open=True)
    ip_history = [
        HostIp(
            ip=row["ip"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
        )
        for row in db.list_host_ips(host_id)
    ]
    recent_events = db.list_recent_events(host_id=host_id, limit=50)
    edges = [
        e for e in db.list_edges()
        if e.src_host_id == host_id or e.dst_host_id == host_id
    ]
    return HostDetail(
        host=host, open_ports=open_ports, ip_history=ip_history,
        edges=edges, recent_events=recent_events,
    )


def register(app: FastAPI) -> None:
    app.include_router(api)
```

- [ ] **Step 4: Wire `register` into `create_app`**

In `src/netmap/server/app.py`, find the comment `# Routes registered in Tasks 15-19 will be added below this comment.` and replace that line with:

```python
    from netmap.server import routes
    routes.register(app)
```

- [ ] **Step 5: Re-run the tests**

Run: `uv run pytest tests/api/test_hosts.py -v`
Expected: all five tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/netmap/server/routes.py src/netmap/server/app.py tests/api/test_hosts.py
git commit -m "feat(server): GET /api/v1/hosts and /api/v1/hosts/{id}"
```

---

### Task 16 — `GET /api/v1/subnets`, `/api/v1/scans`, `/api/v1/events`

**Files:**
- Modify: `src/netmap/server/routes.py`
- Create: `tests/api/test_subnets.py`
- Create: `tests/api/test_scans.py`
- Create: `tests/api/test_events.py`

- [ ] **Step 1: Write the failing tests**

`tests/api/test_subnets.py`:
```python
"""GET /api/v1/subnets — read-only in M2."""
from __future__ import annotations

from datetime import UTC, datetime

from netmap.models import Subnet


def test_get_subnets_returns_all_rows(client, storage):
    storage.insert_subnet(Subnet(
        cidr="192.168.1.0/24", source="config", enabled=True,
        hop_distance=0, first_seen=datetime.now(tz=UTC),
    ))
    storage.insert_subnet(Subnet(
        cidr="10.0.0.0/24", source="discovered", enabled=False,
        hop_distance=1, first_seen=datetime.now(tz=UTC),
    ))

    r = client.get("/api/v1/subnets")
    assert r.status_code == 200
    rows = r.json()
    assert [row["cidr"] for row in rows] == ["192.168.1.0/24", "10.0.0.0/24"]


def test_subnets_mutation_endpoints_not_registered_in_m2(client):
    # M3 will add POST/PATCH/DELETE; M2 returns 405 (method not allowed).
    assert client.post("/api/v1/subnets", json={}).status_code in (404, 405)
    assert client.patch("/api/v1/subnets/1", json={}).status_code in (404, 405)
    assert client.delete("/api/v1/subnets/1").status_code in (404, 405)
```

`tests/api/test_scans.py` (only the GET part for now — POST in Task 17):
```python
"""GET /api/v1/scans — list scans with filters."""
from __future__ import annotations

from datetime import UTC, datetime

from netmap.models import Scan


def _now():
    return datetime.now(tz=UTC)


def test_get_scans_returns_recent_scans(client, storage):
    storage.start_scan(Scan(
        started_at=_now(), source="cli", target="192.168.1.0/24",
        mode="discover", status="ok", hosts_seen=5,
    ))
    storage.start_scan(Scan(
        started_at=_now(), source="cli", target="192.168.1.0/24",
        mode="default", status="error", hosts_seen=0,
    ))

    r = client.get("/api/v1/scans")
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 2


def test_get_scans_filters_by_status(client, storage):
    storage.start_scan(Scan(
        started_at=_now(), source="cli", target="x", mode="discover",
        status="ok", hosts_seen=0,
    ))
    storage.start_scan(Scan(
        started_at=_now(), source="cli", target="x", mode="discover",
        status="error", hosts_seen=0,
    ))

    r = client.get("/api/v1/scans?status=ok")
    assert r.status_code == 200
    rows = r.json()
    assert all(row["status"] == "ok" for row in rows)


def test_get_scans_respects_limit(client, storage):
    for _ in range(5):
        storage.start_scan(Scan(
            started_at=_now(), source="cli", target="x", mode="discover",
            status="ok", hosts_seen=0,
        ))

    r = client.get("/api/v1/scans?limit=2")
    assert r.status_code == 200
    assert len(r.json()) == 2
```

`tests/api/test_events.py`:
```python
"""GET /api/v1/events — list events with filters."""
from __future__ import annotations

from datetime import UTC, datetime

from netmap.models import Event


def _now():
    return datetime.now(tz=UTC)


def test_get_events_returns_all_recent_events(client, storage):
    storage.insert_event(Event(ts=_now(), kind="scan.started"))
    storage.insert_event(Event(ts=_now(), kind="host.new", host_id=1))

    r = client.get("/api/v1/events")
    assert r.status_code == 200
    assert len(r.json()) == 2


def test_get_events_filters_by_kind(client, storage):
    storage.insert_event(Event(ts=_now(), kind="scan.started"))
    storage.insert_event(Event(ts=_now(), kind="host.new", host_id=1))

    r = client.get("/api/v1/events?kind=host.new")
    assert r.status_code == 200
    rows = r.json()
    assert [row["kind"] for row in rows] == ["host.new"]


def test_get_events_filters_by_since(client, storage):
    early = datetime(2026, 1, 1, tzinfo=UTC)
    late = datetime(2026, 5, 25, tzinfo=UTC)
    storage.insert_event(Event(ts=early, kind="scan.started"))
    storage.insert_event(Event(ts=late, kind="host.new", host_id=1))

    r = client.get("/api/v1/events?since=2026-03-01T00:00:00%2B00:00")
    assert r.status_code == 200
    rows = r.json()
    assert [row["kind"] for row in rows] == ["host.new"]
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/api/test_subnets.py tests/api/test_scans.py tests/api/test_events.py -v`
Expected: FAIL — the new routes don't exist.

- [ ] **Step 3: Add the list routes to `routes.py`**

Append to `src/netmap/server/routes.py`, before `def register(app)`:

```python
from datetime import datetime as _dt

from netmap.models import Event, Scan, Subnet


@api.get("/subnets", response_model=list[Subnet])
def get_subnets(request: Request):
    return _state(request).db.list_subnets()


@api.get("/scans", response_model=list[Scan])
def get_scans(
    request: Request,
    status: str | None = Query(default=None),
    since: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
):
    since_dt = _dt.fromisoformat(since) if since else None
    return _state(request).db.list_scans(status=status, since=since_dt, limit=limit)


@api.get("/events", response_model=list[Event])
def get_events(
    request: Request,
    since: str | None = Query(default=None),
    host_id: int | None = Query(default=None),
    kind: str | None = Query(default=None),
    limit: int = Query(default=500, ge=1, le=2000),
):
    db = _state(request).db
    since_dt = _dt.fromisoformat(since) if since else None
    events = db.list_events(since=since_dt, host_id=host_id, limit=limit)
    if kind:
        events = [e for e in events if e.kind == kind]
    return events
```

- [ ] **Step 4: Re-run the tests**

Run: `uv run pytest tests/api/test_subnets.py tests/api/test_scans.py tests/api/test_events.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/server/routes.py tests/api/test_subnets.py tests/api/test_scans.py tests/api/test_events.py
git commit -m "feat(server): GET /api/v1/subnets, /scans, /events"
```

---

### Task 17 — `POST /api/v1/scans`

**Files:**
- Modify: `src/netmap/server/routes.py`
- Modify: `tests/api/test_scans.py`

POST /scans validates each target through `SafetyPolicy`, checks `in_flight`, and dispatches via `loop.maybe_run`. The endpoint returns once the scan row is created and the background task is in flight — it does not await the scan to finish.

- [ ] **Step 1: Write the failing tests**

Append to `tests/api/test_scans.py`:

```python
from ipaddress import IPv4Network

from netmap.models import Subnet
from netmap.scanner.base import ScanMode


def _seed_subnet(storage, cidr: str = "192.168.1.0/24") -> None:
    storage.insert_subnet(Subnet(
        cidr=cidr, source="config", enabled=True,
        hop_distance=0, first_seen=_now(),
    ))


def test_post_scan_with_explicit_targets_returns_scan_id(client, storage, monkeypatch):
    _seed_subnet(storage)

    async def fake_maybe_run(**kwargs):
        return 42
    monkeypatch.setattr("netmap.server.routes.maybe_run", fake_maybe_run)

    r = client.post(
        "/api/v1/scans",
        json={"mode": "discover", "targets": ["192.168.1.0/24"]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["scan_id"] == 42
    assert body["accepted_targets"] == ["192.168.1.0/24"]


def test_post_scan_defaults_to_enabled_subnets_when_targets_omitted(client, storage, monkeypatch):
    _seed_subnet(storage, cidr="10.0.0.0/24")

    captured: dict = {}
    async def fake_maybe_run(*, mode, targets, **kwargs):
        captured["targets"] = [str(t) for t in targets]
        return 7
    monkeypatch.setattr("netmap.server.routes.maybe_run", fake_maybe_run)

    r = client.post("/api/v1/scans", json={"mode": "default"})
    assert r.status_code == 200
    assert captured["targets"] == ["10.0.0.0/24"]


def test_post_scan_rejects_invalid_cidr_with_409(client, monkeypatch):
    async def fake_maybe_run(**kwargs):  # never reached
        return None
    monkeypatch.setattr("netmap.server.routes.maybe_run", fake_maybe_run)

    r = client.post(
        "/api/v1/scans",
        json={"mode": "discover", "targets": ["0.0.0.0/8"]},
    )
    assert r.status_code == 409
    assert "deny_cidrs" in r.json()["detail"]


def test_post_scan_returns_409_when_target_already_in_flight(client, storage, monkeypatch, in_flight):
    _seed_subnet(storage)
    in_flight.add(("discover", "192.168.1.0/24"))

    async def fake_maybe_run(**kwargs):  # never reached
        return None
    monkeypatch.setattr("netmap.server.routes.maybe_run", fake_maybe_run)

    r = client.post(
        "/api/v1/scans",
        json={"mode": "discover", "targets": ["192.168.1.0/24"]},
    )
    assert r.status_code == 409
    assert "already running" in r.json()["detail"]


def test_post_scan_400_when_no_targets_and_no_enabled_subnets(client, monkeypatch):
    async def fake_maybe_run(**kwargs):
        return None
    monkeypatch.setattr("netmap.server.routes.maybe_run", fake_maybe_run)

    r = client.post("/api/v1/scans", json={"mode": "discover"})
    assert r.status_code == 400
    assert "no targets" in r.json()["detail"]
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/api/test_scans.py -v`
Expected: the five new tests FAIL — POST /scans not registered.

- [ ] **Step 3: Implement `POST /scans`**

Append to `src/netmap/server/routes.py`, before `def register(app)`:

```python
from ipaddress import IPv4Network

from netmap.scanner.base import ScanMode
from netmap.scanner.loop import maybe_run
from netmap.scanner.safety import SafetyError, SafetyPolicy, validate_target
from netmap.server.schemas import ScanRequest, ScanResponse


def _policy_from_cfg(cfg) -> SafetyPolicy:
    return SafetyPolicy(
        deny_cidrs=tuple(cfg.safety.deny_cidrs),
        allow_public_scan=cfg.safety.allow_public_scan,
        max_target_hosts=cfg.safety.max_target_hosts,
        max_hop_distance=cfg.safety.max_hop_distance,
    )


@api.post("/scans", response_model=ScanResponse)
async def post_scan(request: Request, req: ScanRequest):
    state = _state(request)
    cfg = state.cfg
    db = state.db
    bus = state.bus
    in_flight = state.in_flight

    cidrs = req.targets
    if not cidrs:
        cidrs = [s.cidr for s in db.list_subnets() if s.enabled]
    if not cidrs:
        raise HTTPException(
            status_code=400,
            detail="no targets supplied and no enabled subnets configured",
        )

    policy = _policy_from_cfg(cfg)
    nets: list[IPv4Network] = []
    for cidr in cidrs:
        try:
            nets.append(validate_target(cidr, policy, confirm=req.confirm))
        except SafetyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    signature = ",".join(sorted(str(n) for n in nets))
    if (req.mode.value, signature) in in_flight:
        raise HTTPException(
            status_code=409,
            detail=f"scan already running on this target ({signature})",
        )

    scan_id = await maybe_run(
        mode=req.mode, targets=nets,
        db=db, bus=bus, cfg=cfg, in_flight=in_flight,
        source="api.post_scan",
    )
    if scan_id is None:
        # Race: another request snuck the same target into in_flight between
        # our check and maybe_run's check. Surface as 409.
        raise HTTPException(
            status_code=409,
            detail=f"scan already running on this target ({signature})",
        )

    return ScanResponse(scan_id=scan_id, accepted_targets=[str(n) for n in nets])
```

- [ ] **Step 4: Re-run the tests**

Run: `uv run pytest tests/api/test_scans.py -v`
Expected: all eight tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/server/routes.py tests/api/test_scans.py
git commit -m "feat(server): POST /api/v1/scans with target validation + in_flight guard"
```

---

### Task 18 — `GET /api/v1/stream` (SSE)

**Files:**
- Modify: `src/netmap/server/routes.py`
- Create: `tests/api/test_sse.py`

`sse-starlette`'s `EventSourceResponse` handles framing + the periodic ping. Each connection gets its own `bus.subscribe()` queue. On disconnect, we `bus.unsubscribe(q)`.

- [ ] **Step 1: Write the failing test**

`tests/api/test_sse.py`:
```python
"""GET /api/v1/stream — Server-Sent Events. Publish event, assert client receives it."""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import pytest

from netmap.models import Event


@pytest.mark.asyncio
async def test_sse_delivers_published_event_to_connected_client(client, bus):
    # `client` (TestClient) is sync; use it as a context manager so the
    # lifespan starts, then drive an async publish through the bus.
    with client.stream("GET", "/api/v1/stream", timeout=3) as response:
        assert response.status_code == 200
        # Spawn a publisher that fires after the connection settles.
        async def fire():
            await asyncio.sleep(0.1)
            await bus.publish(Event(
                ts=datetime.now(tz=UTC), kind="host.new",
                payload={"id": 99},
            ))
        task = asyncio.create_task(fire())

        # Read until we see a `data:` line carrying our event.
        got_event = None
        for line in response.iter_lines():
            if line.startswith("data:"):
                got_event = json.loads(line[len("data:"):].strip())
                break
        await task
        assert got_event is not None
        assert got_event["kind"] == "host.new"
        assert got_event["payload"]["id"] == 99


def test_sse_endpoint_returns_event_stream_content_type(client):
    with client.stream("GET", "/api/v1/stream", timeout=2) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/api/test_sse.py -v`
Expected: FAIL — /stream not registered.

- [ ] **Step 3: Implement the SSE endpoint**

Append to `src/netmap/server/routes.py`, before `def register(app)`:

```python
import asyncio as _asyncio
import json as _json

from sse_starlette.sse import EventSourceResponse


@api.get("/stream")
async def stream(request: Request):
    bus = _state(request).bus
    queue = bus.subscribe()

    async def event_iter():
        try:
            yield {"comment": "connected"}
            while True:
                if await request.is_disconnected():
                    return
                try:
                    event = await _asyncio.wait_for(queue.get(), timeout=30)
                except _asyncio.TimeoutError:
                    # `sse-starlette` adds keepalive comments via the ping=
                    # response param too, but an explicit beat is harmless.
                    yield {"comment": "ping"}
                    continue
                yield {"data": _json.dumps(event.model_dump(mode="json"))}
        finally:
            bus.unsubscribe(queue)

    return EventSourceResponse(event_iter(), ping=30)
```

- [ ] **Step 4: Re-run the tests**

Run: `uv run pytest tests/api/test_sse.py -v`
Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add src/netmap/server/routes.py tests/api/test_sse.py
git commit -m "feat(server): SSE endpoint GET /api/v1/stream over AsyncBus"
```

---

### Task 19 — Static file mount + `GET /`

**Files:**
- Modify: `src/netmap/server/routes.py`
- Modify: `src/netmap/server/app.py`
- Create: `src/netmap/ui/index.html` (1-line placeholder; full file lands in Task 21)
- Create: `src/netmap/ui/styles.css` (1-line placeholder; full file in Task 22)
- Create: `src/netmap/ui/app.js` (1-line placeholder; full file in Tasks 23-26)
- Create: `tests/api/test_static.py`

We register the static mount and `GET /` now so the file pipeline is in place. The UI files start as one-line placeholders that prove the wheel-bundle path works; the real content lands in Phase 5.

- [ ] **Step 1: Create UI placeholders**

`src/netmap/ui/index.html`:
```html
<!doctype html><html><head><meta charset="utf-8"><title>net-map</title></head><body><div id="root">net-map UI loading…</div></body></html>
```

`src/netmap/ui/styles.css`:
```css
/* Placeholder — replaced in Task 22. */
body { background: #020617; color: #E5E7EB; font-family: ui-monospace, monospace; }
```

`src/netmap/ui/app.js`:
```javascript
// Placeholder — replaced in Tasks 23-26.
console.log("net-map UI placeholder");
```

- [ ] **Step 2: Write the failing test**

`tests/api/test_static.py`:
```python
"""Static UI files served from /."""
from __future__ import annotations


def test_root_returns_html_with_netmap_title(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "<title>net-map</title>" in r.text


def test_styles_css_served_under_ui(client):
    r = client.get("/ui/styles.css")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/css")


def test_app_js_served_under_ui(client):
    r = client.get("/ui/app.js")
    assert r.status_code == 200
    assert "javascript" in r.headers["content-type"]
```

- [ ] **Step 3: Run the tests**

Run: `uv run pytest tests/api/test_static.py -v`
Expected: 404s — no static mount registered.

- [ ] **Step 4: Register static mount + `GET /`**

In `src/netmap/server/routes.py`, replace the `def register(app)` function with:

```python
def register(app: FastAPI) -> None:
    from importlib.resources import files

    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    app.include_router(api)

    ui_dir = files("netmap").joinpath("ui")
    index_path = str(ui_dir.joinpath("index.html"))

    app.mount(
        "/ui",
        StaticFiles(directory=str(ui_dir)),
        name="ui",
    )

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(index_path, media_type="text/html")
```

- [ ] **Step 5: Re-run the tests**

Run: `uv run pytest tests/api/test_static.py -v`
Expected: all three PASS.

- [ ] **Step 6: Commit**

```bash
git add src/netmap/server/routes.py src/netmap/ui/index.html src/netmap/ui/styles.css src/netmap/ui/app.js tests/api/test_static.py
git commit -m "feat(server): static mount /ui + GET / serving placeholder UI"
```

---

## Phase 4 — CLI (Task 20)

### Task 20 — `netmap up` command

**Files:**
- Modify: `src/netmap/cli.py`
- Create: `tests/unit/test_cli_up.py`

`netmap up` is mostly a wrapper around `server.app.run(cfg, db_path=..., cli_targets=...)`. The CLI itself takes the flags described in spec §17 (`--bind`, `--port`, `--target`, `--no-open`) and is unit-tested at the help-text + invocation level. The real-process behavior is exercised in Task 27's integration smoke.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_cli_up.py`:
```python
"""`netmap up` CLI — flag parsing and dispatch to server.app.run."""
from __future__ import annotations

from typer.testing import CliRunner

from netmap.cli import app

runner = CliRunner()


def test_up_appears_in_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "up" in result.stdout


def test_up_invokes_server_run_with_cli_args(monkeypatch, tmp_path):
    captured: dict = {}
    def fake_run(cfg, *, db_path, cli_targets):
        captured["bind"] = cfg.server.bind
        captured["port"] = cfg.server.port
        captured["db_path"] = db_path
        captured["cli_targets"] = cli_targets
    monkeypatch.setattr("netmap.server.app.run", fake_run)

    cfg_path = tmp_path / "config.toml"
    db_path = tmp_path / "state.db"
    result = runner.invoke(app, [
        "up",
        "--bind", "127.0.0.1",
        "--port", "9876",
        "--target", "192.168.1.0/24",
        "--db", str(db_path),
        "--config", str(cfg_path),
        "--no-open",
    ])
    assert result.exit_code == 0, result.stdout
    assert captured["bind"] == "127.0.0.1"
    assert captured["port"] == 9876
    assert captured["cli_targets"] == ["192.168.1.0/24"]
    assert captured["db_path"] == db_path


def test_up_defaults_cli_targets_to_none(monkeypatch, tmp_path):
    captured: dict = {}
    def fake_run(cfg, *, db_path, cli_targets):
        captured["cli_targets"] = cli_targets
    monkeypatch.setattr("netmap.server.app.run", fake_run)

    result = runner.invoke(app, [
        "up",
        "--config", str(tmp_path / "c.toml"),
        "--db", str(tmp_path / "s.db"),
        "--no-open",
    ])
    assert result.exit_code == 0
    assert captured["cli_targets"] is None
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/unit/test_cli_up.py -v`
Expected: FAIL — `up` command doesn't exist.

- [ ] **Step 3: Add the `up` command**

In `src/netmap/cli.py`, after the `scan` command (right before the `db_app = ...` line), add:

```python
@app.command()
def up(
    bind: Annotated[
        str | None, typer.Option("--bind", help="Override [server].bind")
    ] = None,
    port: Annotated[
        int | None, typer.Option("--port", help="Override [server].port")
    ] = None,
    target: Annotated[
        list[str] | None,
        typer.Option(
            "--target", "-t",
            help="Explicit CIDR(s) — bypass auto-detect. Pass multiple times.",
        ),
    ] = None,
    db_path: Annotated[Path, typer.Option("--db")] = DEFAULT_DB_PATH,
    config_path: Annotated[Path, typer.Option("--config")] = DEFAULT_CONFIG_PATH,
    open_browser: Annotated[
        bool,
        typer.Option(
            "--open/--no-open",
            help="Open the UI in the default browser after startup.",
        ),
    ] = True,
) -> None:
    """Start the foreground web server + scan loop.

    Requires root or CAP_NET_RAW + CAP_NET_ADMIN. Defaults to 127.0.0.1:8765;
    auto-detects the local CIDR if no --target is given and the subnet table
    is empty. Ctrl-C stops everything cleanly.
    """
    import webbrowser

    from netmap.server import app as server_app

    cfg = load_config(config_path)
    if bind is not None:
        cfg.server.bind = bind
    if port is not None:
        cfg.server.port = port

    cli_targets = list(target) if target else None

    if open_browser:
        url = f"http://{cfg.server.bind}:{cfg.server.port}/"
        try:
            webbrowser.open(url, new=2)
        except webbrowser.Error:
            typer.echo(f"open {url} in your browser", err=True)

    db_path.parent.mkdir(parents=True, exist_ok=True)
    server_app.run(cfg, db_path=db_path, cli_targets=cli_targets)
```

- [ ] **Step 4: Re-run the tests**

Run: `uv run pytest tests/unit/test_cli_up.py -v`
Expected: all three PASS.

- [ ] **Step 5: Run all unit + API tests, confirm nothing regressed**

Run: `uv run pytest -m "not integration" -q`
Expected: all green. Total ~135 tests passing (rough estimate).

- [ ] **Step 6: Commit**

```bash
git add src/netmap/cli.py tests/unit/test_cli_up.py
git commit -m "feat(cli): add `netmap up` command driving server.app.run"
```

---

## Phase 5 — Frontend (Tasks 21-26)

No automated tests in M2 (per spec §16.4). Each task here is **write the file in full + manual smoke**: start `sudo netmap up` against a real LAN, open the browser, confirm the UI renders the slice this task adds. The manual smoke is also captured as a checklist in Task 28.

### Task 21 — `ui/index.html` — shell + inlined icon sprite

**Files:**
- Modify: `src/netmap/ui/index.html`

Replace the placeholder with the full shell. Pinned CDN URLs (no `@latest`). The SVG icon sprite is inlined as a single `<svg display="none">` block with `<symbol>` definitions — each device-type icon referenced via `<svg><use href="#ic-router"/></svg>` from Cytoscape's node rendering and the host-detail panel.

- [ ] **Step 1: Write the full file**

Replace the contents of `src/netmap/ui/index.html` with:

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>net-map</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link rel="stylesheet"
        href="https://fonts.googleapis.com/css2?family=Geist+Mono:wght@400;500;600;700&display=swap" />
  <link rel="stylesheet" href="/ui/styles.css" />
  <script src="https://unpkg.com/cytoscape@3.30.0/dist/cytoscape.min.js"></script>
  <script src="https://unpkg.com/layout-base@2.0.1/layout-base.js"></script>
  <script src="https://unpkg.com/cose-base@2.2.0/cose-base.js"></script>
  <script src="https://unpkg.com/cytoscape-cose-bilkent@4.1.0/cytoscape-cose-bilkent.js"></script>
</head>
<body>
  <!-- Device-type icon sprite. Referenced via <use href="#ic-router"/> etc. -->
  <svg width="0" height="0" style="position:absolute" aria-hidden="true">
    <defs>
      <symbol id="ic-router" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="13" width="18" height="6" rx="1" />
        <path d="M7 17h.01M11 17h.01" />
        <path d="M12 13V7" />
        <path d="M8 7l4-4 4 4" />
      </symbol>
      <symbol id="ic-server" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="4" width="18" height="6" rx="1" />
        <rect x="3" y="14" width="18" height="6" rx="1" />
        <path d="M7 7h.01M7 17h.01" />
      </symbol>
      <symbol id="ic-nas" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="4" width="18" height="16" rx="1" />
        <circle cx="8" cy="8" r="1" />
        <circle cx="8" cy="12" r="1" />
        <circle cx="8" cy="16" r="1" />
      </symbol>
      <symbol id="ic-laptop" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
        <rect x="4" y="5" width="16" height="11" rx="1" />
        <path d="M2 19h20" />
      </symbol>
      <symbol id="ic-phone" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
        <rect x="7" y="2" width="10" height="20" rx="2" />
        <path d="M11 18h2" />
      </symbol>
      <symbol id="ic-printer" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
        <path d="M6 9V3h12v6" />
        <rect x="3" y="9" width="18" height="8" rx="1" />
        <rect x="6" y="14" width="12" height="7" />
      </symbol>
      <symbol id="ic-ap" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
        <path d="M5 12.55a11 11 0 0 1 14 0" />
        <path d="M8.5 16.5a6 6 0 0 1 7 0" />
        <path d="M2 8.82a15 15 0 0 1 20 0" />
        <circle cx="12" cy="20" r="1" />
      </symbol>
      <symbol id="ic-camera" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
        <path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8" />
        <circle cx="12" cy="13" r="3" />
        <path d="M4 8l4-4h4" />
      </symbol>
      <symbol id="ic-iot" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
        <rect x="5" y="5" width="14" height="14" rx="1" />
        <path d="M9 1v4M15 1v4M9 19v4M15 19v4M1 9h4M1 15h4M19 9h4M19 15h4" />
      </symbol>
      <symbol id="ic-unknown" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"
              stroke-dasharray="2 2">
        <circle cx="12" cy="12" r="9" />
        <path d="M9.5 9a2.5 2.5 0 0 1 5 0c0 2-2.5 2-2.5 4" />
        <path d="M12 17h.01" />
      </symbol>
    </defs>
  </svg>

  <div id="app">
    <header class="topbar">
      <div class="brand"><span class="cursor">▌</span>net-map</div>
      <div class="crumb" id="crumb">~/networks # discover · waiting</div>
      <div class="kpis" id="kpis"></div>
      <button class="scan-now" id="scanNowBtn" type="button">scan now</button>
      <div class="live" id="liveIndicator" aria-live="polite">live</div>
    </header>

    <aside class="sidebar">
      <h2 class="sidebar-h">subnets</h2>
      <ul class="subnet-list" id="subnetList"></ul>
      <p class="sidebar-m3-note">[M3] discover via gw</p>
    </aside>

    <main class="canvas">
      <div id="cy"></div>
      <div class="canvas-empty" id="canvasEmpty">
        <p>waiting for first scan…</p>
      </div>
    </main>

    <section class="detail" id="detail" aria-label="host detail">
      <div class="detail-empty" id="detailEmpty">select a host on the graph to inspect it</div>
      <div class="detail-body" id="detailBody" hidden></div>
    </section>

    <section class="timeline" aria-label="event timeline">
      <h2 class="timeline-h">events</h2>
      <ol class="timeline-list" id="timelineList"></ol>
    </section>

    <div class="toast-stack" id="toastStack" aria-live="polite"></div>
  </div>

  <!-- Accessibility mirror: hidden table of hosts for screen readers. -->
  <table id="srHostTable" class="sr-only" aria-label="hosts (text view)"></table>

  <script src="/ui/app.js" defer></script>
</body>
</html>
```

- [ ] **Step 2: Manual smoke — file loads, icons render**

Run (in one shell):
```bash
sudo uv run netmap up --no-open
```
In another shell, run:
```bash
curl -sf http://127.0.0.1:8765/ | grep -F '<title>net-map</title>'
curl -sf http://127.0.0.1:8765/ | grep -F 'id="ic-router"'
```
Expected: both `grep`s match. Stop with Ctrl-C in the first shell.

- [ ] **Step 3: Commit**

```bash
git add src/netmap/ui/index.html
git commit -m "feat(ui): index.html shell + inlined Lucide-style device icon sprite"
```

---

### Task 22 — `ui/styles.css` — Terminal Console stylesheet

**Files:**
- Modify: `src/netmap/ui/styles.css`

Implements the visual identity frozen in spec §12.3: pure-black canvas, Geist Mono, phosphor-green accent. Grid layout for topbar / sidebar / canvas / detail / timeline. Risk colors reserved for port rows.

- [ ] **Step 1: Write the full file**

Replace the contents of `src/netmap/ui/styles.css` with:

```css
:root {
  --bg:         #020617;
  --surface:    #0B1220;
  --surface-2:  #0F1A2E;
  --border:     #1F2937;
  --text:       #E5E7EB;
  --text-muted: #6B7280;
  --accent:     #22C55E;
  --risk-red:   #F87171;
  --risk-yel:   #FBBF24;
  --risk-grn:   #22C55E;
  --risk-gray:  #6B7280;

  --topbar-h:    44px;
  --sidebar-w:  200px;
  --detail-w:   320px;
  --timeline-h: 140px;
}

* { box-sizing: border-box; }

html, body {
  margin: 0; padding: 0;
  background: var(--bg); color: var(--text);
  font-family: 'Geist Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 13px; line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

button { font-family: inherit; }

a, button { color: inherit; }

:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}

#app {
  display: grid;
  grid-template-columns: var(--sidebar-w) 1fr var(--detail-w);
  grid-template-rows: var(--topbar-h) 1fr var(--timeline-h);
  grid-template-areas:
    "topbar topbar topbar"
    "sidebar canvas detail"
    "timeline timeline timeline";
  height: 100vh;
}

/* ------------- topbar ------------- */
.topbar {
  grid-area: topbar;
  display: flex; align-items: center;
  gap: 18px;
  padding: 0 16px;
  border-bottom: 1px solid var(--border);
  background: var(--surface);
}
.brand {
  color: var(--accent);
  font-weight: 600; font-size: 14px;
  display: flex; align-items: center;
}
.brand .cursor {
  margin-right: 6px;
  animation: blink 1.5s steps(2) infinite;
}
@keyframes blink { 50% { opacity: 0.3; } }
.crumb {
  color: var(--text-muted); font-size: 11px;
  flex: 0 0 auto;
}
.kpis {
  flex: 1 1 auto;
  display: flex; gap: 14px;
  font-size: 11px; color: var(--text-muted);
}
.kpi { display: flex; gap: 6px; align-items: center; }
.kpi .v { color: var(--text); font-weight: 500; }
.kpi.risk .v { color: var(--risk-red); }

.scan-now {
  background: transparent;
  color: var(--accent);
  border: 1px solid var(--accent);
  padding: 4px 10px;
  font-size: 11px; font-weight: 600;
  cursor: pointer;
  text-transform: lowercase;
}
.scan-now:hover { background: rgba(34,197,94,0.08); }
.scan-now:disabled { opacity: 0.4; cursor: not-allowed; }

.live {
  font-size: 10px; color: var(--accent);
  display: flex; align-items: center; gap: 6px;
}
.live::before {
  content: ""; width: 6px; height: 6px; border-radius: 50%;
  background: var(--accent);
  box-shadow: 0 0 6px var(--accent);
  animation: pulse 1.4s ease-in-out infinite;
}
.live[data-state="reconnecting"]::before { background: var(--risk-yel); box-shadow: 0 0 6px var(--risk-yel); }
.live[data-state="reconnecting"] { color: var(--risk-yel); }
@keyframes pulse { 50% { opacity: 0.4; } }

/* ------------- sidebar ------------- */
.sidebar {
  grid-area: sidebar;
  background: var(--surface);
  border-right: 1px solid var(--border);
  padding: 14px 12px;
  overflow-y: auto;
}
.sidebar-h {
  margin: 0 0 8px;
  font-size: 10px; font-weight: 500;
  color: var(--text-muted); text-transform: lowercase;
  letter-spacing: 0.5px;
}
.subnet-list { list-style: none; margin: 0; padding: 0; }
.subnet-list li {
  padding: 6px 8px;
  font-size: 11px;
  border-left: 2px solid transparent;
  cursor: pointer;
  color: var(--text);
}
.subnet-list li:hover { background: var(--surface-2); }
.subnet-list li[aria-current="true"] {
  border-left-color: var(--accent);
  background: var(--surface-2);
}
.subnet-list .cidr { color: var(--text); }
.subnet-list .meta { color: var(--text-muted); font-size: 10px; }
.sidebar-m3-note {
  margin-top: 14px; padding: 6px 8px;
  font-size: 10px; color: var(--text-muted);
  border: 1px dashed var(--border);
}

/* ------------- canvas ------------- */
.canvas {
  grid-area: canvas;
  position: relative;
  background: var(--bg);
  overflow: hidden;
}
#cy { position: absolute; inset: 0; }

.canvas::before {
  content: ""; position: absolute; inset: 0; pointer-events: none;
  background: repeating-linear-gradient(
    to bottom, transparent 0, transparent 3px,
    rgba(34,197,94,0.025) 3px, rgba(34,197,94,0.025) 4px);
}

.canvas-empty {
  position: absolute; inset: 0;
  display: flex; align-items: center; justify-content: center;
  color: var(--text-muted); font-size: 12px;
  pointer-events: none;
}

/* ------------- host detail ------------- */
.detail {
  grid-area: detail;
  border-left: 1px solid var(--border);
  background: var(--surface);
  overflow-y: auto;
}
.detail-empty {
  padding: 16px;
  color: var(--text-muted); font-size: 11px;
}
.detail-body { padding: 0; }
.detail-section {
  border-bottom: 1px solid var(--border);
}
.detail-section .section-h {
  margin: 0;
  padding: 8px 14px;
  font-size: 11px; font-weight: 500;
  color: var(--text-muted); text-transform: lowercase;
  cursor: pointer;
  display: flex; align-items: center; gap: 6px;
}
.detail-section .section-h::before {
  content: "▾"; font-size: 9px; color: var(--text-muted);
}
.detail-section[data-collapsed="true"] .section-h::before { content: "▸"; }
.detail-section[data-collapsed="true"] .section-body { display: none; }
.detail-section .section-body { padding: 4px 14px 12px; }

.detail .host-head {
  padding: 14px;
  display: flex; align-items: flex-start; gap: 10px;
}
.detail .host-icon {
  width: 28px; height: 28px;
  color: var(--text);
}
.detail .host-meta { display: grid; gap: 2px; font-size: 12px; }
.detail .host-meta .ip { color: var(--text); font-weight: 500; }
.detail .host-meta .mac { color: var(--text-muted); font-size: 10px; }
.detail .host-meta .vendor { color: var(--text-muted); font-size: 10px; }

.port-row {
  display: grid; grid-template-columns: 14px 70px 50px 1fr;
  align-items: center; gap: 6px;
  padding: 3px 0 3px 8px;
  font-size: 11px;
  border-left: 2px solid var(--risk-gray);
  background: rgba(107,114,128,0.03);
}
.port-row.high  { border-left-color: var(--risk-red); background: rgba(248,113,113,0.05); }
.port-row.elev  { border-left-color: var(--risk-yel); background: rgba(251,191,36,0.05); }
.port-row.norm  { border-left-color: var(--risk-grn); background: rgba(34,197,94,0.04); }
.port-row .rl   { font-size: 9px; text-transform: lowercase; color: var(--text-muted); }
.port-row.high .rl { color: var(--risk-red); }
.port-row.elev .rl { color: var(--risk-yel); }
.port-row.norm .rl { color: var(--risk-grn); }

.ip-history-row, .event-row {
  font-size: 11px; padding: 2px 0;
  color: var(--text); display: flex; gap: 8px;
}
.ip-history-row .meta, .event-row .ts { color: var(--text-muted); font-size: 10px; }

.detail-disabled-note {
  font-size: 10px; color: var(--text-muted);
  padding: 6px 0; font-style: italic;
}

/* ------------- timeline ------------- */
.timeline {
  grid-area: timeline;
  border-top: 1px solid var(--border);
  background: var(--surface);
  display: flex; flex-direction: column;
  overflow: hidden;
}
.timeline-h {
  margin: 0; padding: 6px 16px;
  font-size: 10px; font-weight: 500;
  color: var(--text-muted); text-transform: lowercase;
  border-bottom: 1px solid var(--border);
}
.timeline-list {
  list-style: none; margin: 0; padding: 4px 0;
  overflow-y: auto;
  font-size: 11px;
}
.timeline-list li {
  padding: 2px 16px;
  display: grid; grid-template-columns: 70px 110px 1fr;
  gap: 10px; align-items: baseline;
}
.timeline-list .ts { color: var(--text-muted); font-size: 10px; }
.timeline-list .kind { color: var(--accent); font-size: 10px; text-transform: lowercase; }
.timeline-list .kind.risk { color: var(--risk-red); }
.timeline-list .detail-text { color: var(--text); }

/* ------------- toast ------------- */
.toast-stack {
  position: fixed; right: 16px; bottom: calc(var(--timeline-h) + 12px);
  display: grid; gap: 6px; z-index: 100;
}
.toast {
  background: var(--surface-2);
  border: 1px solid var(--risk-red);
  color: var(--text);
  padding: 8px 12px; font-size: 11px;
  max-width: 320px;
}
.toast.error { border-color: var(--risk-red); }
.toast.info  { border-color: var(--accent); }

.sr-only {
  position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
  overflow: hidden; clip: rect(0,0,0,0); border: 0;
}

@media (prefers-reduced-motion: reduce) {
  .canvas::before { background: none; }
  .brand .cursor { animation: none; }
  .live::before { animation: none; }
}
```

- [ ] **Step 2: Manual smoke**

Restart `sudo uv run netmap up --no-open`, browse to `http://127.0.0.1:8765`. The page should render with the dark background, monospace text, topbar visible, sidebar with "subnets" heading, an empty-canvas message. Stop with Ctrl-C.

- [ ] **Step 3: Commit**

```bash
git add src/netmap/ui/styles.css
git commit -m "feat(ui): Terminal Console stylesheet (palette tokens + grid layout + risk colors)"
```

---

### Task 23 — `ui/app.js` — Section 1: state + API client + bootstrap

**Files:**
- Modify: `src/netmap/ui/app.js`

This replaces the placeholder with the foundation: the `State` singleton, the `api.*` fetch wrappers, port-risk classifier, device-icon resolver, and the `bootstrap()` entry that runs on `DOMContentLoaded`. The next three tasks append further sections to the same file.

- [ ] **Step 1: Write the file**

Replace the contents of `src/netmap/ui/app.js` with:

```javascript
// net-map UI — section 1: state, API client, helpers, bootstrap.
// Sections 2-4 (cytoscape, SSE, host-detail/timeline) are appended below.

"use strict";

const State = {
  hosts: new Map(),          // id -> HostSummary
  hostDetail: null,          // HostDetail | null
  subnets: [],
  events: [],                // ring buffer, newest first, capped at 200
  selectedHostId: null,
  selectedSubnetId: null,
  scanning: false,
  cy: null,                  // cytoscape instance
  sse: null,                 // EventSource | null
  lastEventTs: null,         // ISO string for catch-up on reconnect
  sseBackoffMs: 1000,
};

const TIMELINE_CAP = 200;

// -------------------- helpers --------------------

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "dataset") for (const [dk, dv] of Object.entries(v)) node.dataset[dk] = dv;
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else if (v === false || v == null) continue;
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children) {
    if (c == null || c === false) continue;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

function fmtRelative(iso) {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  const ageS = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (ageS < 60) return ageS + "s ago";
  if (ageS < 3600) return Math.floor(ageS / 60) + "m ago";
  return Math.floor(ageS / 3600) + "h ago";
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour12: false });
}

// Device-icon resolver: returns one of the <symbol id="..."> names defined in index.html.
function iconForDevice(deviceType) {
  if (deviceType === "router") return "ic-router";
  if (deviceType === "server") return "ic-server";
  if (deviceType === "endpoint") return "ic-laptop";
  if (deviceType === "iot") return "ic-iot";
  return "ic-unknown";
}

// Port-risk classifier (pure). High → SMB / RDP / Telnet / unauth DB.
// Elev → SSH, admin web UIs (9000–9999). Normal → HTTP family. Info → everything else.
const RISK_HIGH_TCP = new Set([23, 135, 139, 445, 1433, 3306, 3389, 5432, 27017]);
const RISK_NORM_TCP = new Set([80, 443, 8080, 8443]);

function portRisk(proto, port) {
  if (proto === "tcp") {
    if (RISK_HIGH_TCP.has(port)) return { tier: "high", label: "high" };
    if (port === 22)             return { tier: "elev", label: "elev" };
    if (port >= 9000 && port < 10000) return { tier: "elev", label: "elev" };
    if (RISK_NORM_TCP.has(port)) return { tier: "norm", label: "normal" };
  }
  return { tier: "info", label: "info" };
}

// -------------------- API client --------------------

async function fetchJson(path, opts = {}) {
  const r = await fetch(path, { credentials: "same-origin", ...opts });
  if (!r.ok) {
    let detail = `${r.status} ${r.statusText}`;
    try { detail = (await r.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  return r.json();
}

const api = {
  hosts: ({ subnet, q } = {}) => {
    const p = new URLSearchParams();
    if (subnet != null) p.set("subnet", subnet);
    if (q) p.set("q", q);
    const qs = p.toString();
    return fetchJson("/api/v1/hosts" + (qs ? "?" + qs : ""));
  },
  hostDetail: (id) => fetchJson("/api/v1/hosts/" + id),
  subnets: () => fetchJson("/api/v1/subnets"),
  scans: () => fetchJson("/api/v1/scans?limit=50"),
  events: ({ since, limit = 200 } = {}) => {
    const p = new URLSearchParams();
    if (since) p.set("since", since);
    p.set("limit", String(limit));
    return fetchJson("/api/v1/events?" + p.toString());
  },
  postScan: (body) => fetchJson("/api/v1/scans", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }),
};

// -------------------- toast --------------------

function toast(message, { kind = "error", ms = 5000 } = {}) {
  const stack = $("#toastStack");
  if (!stack) return;
  const t = el("div", { class: "toast " + kind, role: "status" }, message);
  stack.appendChild(t);
  setTimeout(() => t.remove(), ms);
}

// -------------------- topbar / sidebar render --------------------

function renderTopbar() {
  const crumb = $("#crumb");
  const kpis = $("#kpis");
  const live = $("#liveIndicator");
  const btn = $("#scanNowBtn");

  const hostCount = State.hosts.size;
  let openPorts = 0;
  let risk = 0;
  for (const h of State.hosts.values()) {
    openPorts += h.open_port_count || 0;
  }
  if (State.hostDetail) {
    for (const p of State.hostDetail.open_ports || []) {
      const r = portRisk(p.protocol, p.number);
      if (r.tier === "high") risk += 1;
    }
  }

  const sub = State.subnets.find((s) => s.id === State.selectedSubnetId);
  const subnetLabel = sub ? sub.cidr : (State.subnets[0]?.cidr || "—");
  const mode = State.scanning ? "scanning" : "discover";
  crumb.textContent = `~/networks # ${mode} · ${hostCount} hosts · ${subnetLabel}`;

  kpis.replaceChildren(
    el("div", { class: "kpi" }, "hosts ", el("span", { class: "v" }, String(hostCount))),
    el("div", { class: "kpi" }, "ports ", el("span", { class: "v" }, String(openPorts))),
    el("div", { class: "kpi risk" }, "risk ", el("span", { class: "v" }, String(risk))),
  );

  btn.disabled = State.scanning;
  btn.textContent = State.scanning ? "scanning…" : "scan now";
  live.dataset.state = State.sse && State.sse.readyState === 1 ? "live" : "reconnecting";
  live.textContent = live.dataset.state === "live" ? "live" : "reconnecting…";
}

function renderSidebar() {
  const list = $("#subnetList");
  list.replaceChildren();
  for (const s of State.subnets) {
    list.appendChild(el(
      "li",
      {
        "aria-current": s.id === State.selectedSubnetId ? "true" : "false",
        onclick: () => {
          State.selectedSubnetId =
            State.selectedSubnetId === s.id ? null : s.id;
          renderSidebar(); renderGraph();
        },
      },
      el("div", { class: "cidr" }, s.cidr),
      el("div", { class: "meta" },
        `${s.source} · hop ${s.hop_distance}${s.enabled ? "" : " · disabled"}`),
    ));
  }
}

// -------------------- bootstrap --------------------

async function bootstrap() {
  try {
    const [hosts, subnets] = await Promise.all([api.hosts(), api.subnets()]);
    State.subnets = subnets;
    State.hosts.clear();
    for (const h of hosts) State.hosts.set(h.id, h);

    const initialEvents = await api.events({ limit: 50 });
    for (const ev of initialEvents.reverse()) appendEvent(ev);

    initGraph();         // section 2
    renderSidebar();
    renderTopbar();
    renderGraph();       // section 2

    connectSse();        // section 3

    $("#scanNowBtn").addEventListener("click", onScanNow);
  } catch (exc) {
    toast("bootstrap failed: " + exc.message);
    console.error(exc);
  }
}

async function onScanNow() {
  try {
    await api.postScan({ mode: "default" });
  } catch (exc) {
    toast("scan request rejected: " + exc.message);
  }
}

window.addEventListener("DOMContentLoaded", bootstrap);

// -------------------- placeholders for sections 2-4 --------------------
// These will be replaced by the real implementations in Tasks 24-26.
function initGraph() {}
function renderGraph() {}
function connectSse() {}
function appendEvent(_ev) {}
```

- [ ] **Step 2: Manual smoke**

Restart `sudo uv run netmap up --no-open`. Open http://127.0.0.1:8765 in the browser. Open DevTools console.

Expected: page renders without JS errors. The topbar shows "0 hosts · —"; the sidebar shows "subnets" header with no rows (no subnets yet). No errors in console.

- [ ] **Step 3: Commit**

```bash
git add src/netmap/ui/app.js
git commit -m "feat(ui): app.js section 1 — State, API client, helpers, bootstrap"
```

---

### Task 24 — `ui/app.js` — Section 2: Cytoscape graph + node selection

**Files:**
- Modify: `src/netmap/ui/app.js`

Replaces the `initGraph` / `renderGraph` placeholders with the real implementation: cose-bilkent layout, compound parent nodes per CIDR, host nodes with device-icon backgrounds (rendered as inline SVG data URIs from the `<symbol>` defs), click-to-select wiring.

- [ ] **Step 1: Replace the placeholder block in `app.js`**

In `src/netmap/ui/app.js`, find the comment line:
```
// -------------------- placeholders for sections 2-4 --------------------
```
Replace from that line through the end of the file with:

```javascript
// -------------------- section 2: Cytoscape graph --------------------

function _registerCoseBilkent() {
  if (window.cytoscape && window.cytoscapeCoseBilkent) {
    cytoscape.use(window.cytoscapeCoseBilkent);
  }
}

// Inline an <svg><use href="#ic-router"/></svg> as a data URI suitable for
// Cytoscape's `background-image`. Cytoscape clones the document node so we
// can't directly reference `<use href>` — we serialize the resolved symbol.
const ICON_SVG_CACHE = new Map();
function iconDataUri(name, color) {
  const key = `${name}|${color}`;
  if (ICON_SVG_CACHE.has(key)) return ICON_SVG_CACHE.get(key);
  const symbol = document.getElementById(name);
  if (!symbol) return "";
  const viewBox = symbol.getAttribute("viewBox") || "0 0 24 24";
  const inner = symbol.innerHTML;
  const svg =
    `<svg xmlns='http://www.w3.org/2000/svg' viewBox='${viewBox}' ` +
    `fill='none' stroke='${color}' stroke-width='1.6' ` +
    `stroke-linecap='round' stroke-linejoin='round'>${inner}</svg>`;
  const uri = "data:image/svg+xml;utf8," + encodeURIComponent(svg);
  ICON_SVG_CACHE.set(key, uri);
  return uri;
}

function hostNodeColor(h) {
  // Risk dominates color. Default = text. Trusted hosts get the accent.
  // Heuristic: any open port -> normal; trusted overrides; otherwise muted.
  if (h.trusted) return getCss("--accent");
  if ((h.open_port_count || 0) > 0) return getCss("--text");
  return getCss("--text-muted");
}

function getCss(varname) {
  return getComputedStyle(document.documentElement).getPropertyValue(varname).trim();
}

function initGraph() {
  _registerCoseBilkent();
  State.cy = cytoscape({
    container: document.getElementById("cy"),
    wheelSensitivity: 0.15,
    minZoom: 0.3, maxZoom: 3.0,
    style: [
      {
        selector: "node[type='subnet']",
        style: {
          "background-color": "transparent",
          "border-color": getCss("--border"),
          "border-style": "dashed",
          "border-width": 1,
          "shape": "round-rectangle",
          "label": "data(label)",
          "text-valign": "top",
          "text-halign": "left",
          "text-margin-x": 6,
          "text-margin-y": 4,
          "color": getCss("--text-muted"),
          "font-size": 10,
          "font-family": "Geist Mono, monospace",
          "padding": 16,
        },
      },
      {
        selector: "node[type='host']",
        style: {
          "shape": "round-rectangle",
          "width": 36, "height": 36,
          "background-color": getCss("--surface"),
          "background-image": "data(iconUri)",
          "background-fit": "contain",
          "background-clip": "none",
          "border-color": getCss("--border"),
          "border-width": 1,
          "label": "data(label)",
          "text-valign": "bottom",
          "text-margin-y": 6,
          "color": getCss("--text"),
          "font-size": 10,
          "font-family": "Geist Mono, monospace",
        },
      },
      {
        selector: "node[type='host'][risk='high']",
        style: { "border-color": getCss("--risk-red"), "border-width": 2 },
      },
      {
        selector: "node[type='host'][risk='elev']",
        style: { "border-color": getCss("--risk-yel") },
      },
      {
        selector: "node:selected",
        style: {
          "border-color": getCss("--accent"),
          "border-width": 2,
        },
      },
      {
        selector: "edge",
        style: {
          "width": 1,
          "line-color": getCss("--border"),
          "curve-style": "bezier",
        },
      },
      {
        selector: "edge[kind='gateway']",
        style: { "width": 2, "line-color": getCss("--accent") },
      },
    ],
  });

  State.cy.on("tap", "node[type='host']", (evt) => {
    const id = Number(evt.target.id().replace(/^h/, ""));
    selectHost(id);
  });
  State.cy.on("tap", (evt) => {
    if (evt.target === State.cy) selectHost(null);
  });
}

function _maxRiskFor(host) {
  // We only know open ports from host detail; in the summary view we
  // approximate via open_port_count (any open ports → "norm"). Real risk
  // colors come once the user opens the host detail.
  return (host.open_port_count || 0) > 0 ? "norm" : "info";
}

function renderGraph() {
  if (!State.cy) return;
  const cy = State.cy;
  cy.batch(() => {
    cy.elements().remove();

    const subnetById = new Map(State.subnets.map((s) => [s.id, s]));
    const subnetByCidr = new Map(State.subnets.map((s) => [s.cidr, s]));
    for (const s of State.subnets) {
      cy.add({
        group: "nodes",
        data: { id: "s" + s.id, type: "subnet", label: s.cidr },
      });
    }

    for (const h of State.hosts.values()) {
      const parent = _subnetForIp(h.primary_ip, State.subnets);
      cy.add({
        group: "nodes",
        data: {
          id: "h" + h.id, type: "host",
          parent: parent ? "s" + parent.id : undefined,
          label: h.hostname || h.primary_ip,
          iconUri: iconDataUri(iconForDevice(h.device_type), hostNodeColor(h)),
          risk: _maxRiskFor(h),
        },
      });
    }

    cy.layout({
      name: "cose-bilkent",
      animate: false,
      nodeRepulsion: 4500,
      idealEdgeLength: 80,
      tile: true,
      padding: 30,
    }).run();
  });

  $("#canvasEmpty").hidden = State.hosts.size > 0;
}

function _subnetForIp(ip, subnets) {
  // Lightweight CIDR membership check (IPv4). Returns first matching subnet.
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => isNaN(n))) return null;
  const ipInt = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  for (const s of subnets) {
    const [base, maskStr] = s.cidr.split("/");
    const baseParts = base.split(".").map(Number);
    if (baseParts.length !== 4 || baseParts.some((n) => isNaN(n))) continue;
    const baseInt = ((baseParts[0] << 24) | (baseParts[1] << 16) |
                     (baseParts[2] << 8) | baseParts[3]) >>> 0;
    const mask = (~((1 << (32 - Number(maskStr))) - 1)) >>> 0;
    if ((ipInt & mask) === (baseInt & mask)) return s;
  }
  return null;
}

function selectHost(id) {
  State.selectedHostId = id;
  if (State.cy) {
    State.cy.elements(":selected").unselect();
    if (id != null) {
      const node = State.cy.getElementById("h" + id);
      if (node && node.length) node.select();
    }
  }
  if (id == null) {
    State.hostDetail = null;
    renderHostDetail();
    return;
  }
  api.hostDetail(id).then((d) => {
    State.hostDetail = d;
    renderHostDetail();
    renderTopbar();
  }).catch((exc) => toast("could not load host: " + exc.message));
}

// -------------------- section 3: SSE + reducer (Task 25) --------------------
function connectSse() {}

// -------------------- section 4: host detail + timeline (Task 26) --------------------
function renderHostDetail() {}
function appendEvent(_ev) {}
```

- [ ] **Step 2: Manual smoke**

Restart `sudo uv run netmap up --no-open`. Wait ~60s for first discover scan to populate hosts (or trigger one manually via `curl -X POST http://127.0.0.1:8765/api/v1/scans -d '{"mode":"discover"}' -H content-type:application/json`).

Refresh the browser. Expected: subnet-grouped graph appears, hosts are nodes with icons, clicking a host highlights it with the accent border. No JS errors in console.

- [ ] **Step 3: Commit**

```bash
git add src/netmap/ui/app.js
git commit -m "feat(ui): app.js section 2 — Cytoscape graph with cose-bilkent + device icons"
```

---

### Task 25 — `ui/app.js` — Section 3: SSE client + reducer

**Files:**
- Modify: `src/netmap/ui/app.js`

Replaces the `connectSse` placeholder with the real implementation: single `EventSource`, per-kind reducer, exponential-backoff reconnect (1 s → 30 s cap, reset on `onopen`), catch-up via `/api/v1/hosts` + `/api/v1/events?since=...` after each reconnect.

- [ ] **Step 1: Replace the `connectSse` placeholder**

In `src/netmap/ui/app.js`, find the line:
```
// -------------------- section 3: SSE + reducer (Task 25) --------------------
function connectSse() {}
```
Replace those two lines with:

```javascript
// -------------------- section 3: SSE + reducer --------------------

function connectSse() {
  if (State.sse) {
    try { State.sse.close(); } catch (_) {}
  }
  const sse = new EventSource("/api/v1/stream");
  State.sse = sse;

  sse.onopen = async () => {
    State.sseBackoffMs = 1000;
    renderTopbar();
    // Catch up: refetch hosts + missed events.
    try {
      const hosts = await api.hosts();
      State.hosts.clear();
      for (const h of hosts) State.hosts.set(h.id, h);
      if (State.lastEventTs) {
        const missed = await api.events({ since: State.lastEventTs, limit: 200 });
        for (const ev of missed.reverse()) reduceEvent(ev, { backfill: true });
      }
      renderGraph(); renderTopbar();
    } catch (exc) {
      toast("catch-up failed: " + exc.message);
    }
  };

  sse.onmessage = (msg) => {
    if (!msg.data) return;
    let ev;
    try { ev = JSON.parse(msg.data); }
    catch (_) { return; }
    State.lastEventTs = ev.ts;
    reduceEvent(ev, { backfill: false });
  };

  sse.onerror = () => {
    sse.close();
    State.sse = null;
    renderTopbar();
    const backoff = State.sseBackoffMs;
    State.sseBackoffMs = Math.min(backoff * 2, 30000);
    setTimeout(connectSse, backoff);
  };
}

function reduceEvent(ev, { backfill = false } = {}) {
  switch (ev.kind) {
    case "host.new": {
      if (ev.host_id != null) {
        api.hosts().then((hs) => {
          State.hosts.clear();
          for (const h of hs) State.hosts.set(h.id, h);
          renderGraph(); renderTopbar();
        });
      }
      break;
    }
    case "ip.changed": {
      if (ev.host_id != null) {
        api.hostDetail(ev.host_id).then((d) => {
          const summary = {
            id: d.host.id, mac: d.host.mac, primary_ip: d.host.primary_ip,
            hostname: d.host.hostname, vendor: d.host.vendor,
            device_type: d.host.device_type, trusted: d.host.trusted,
            open_port_count: d.open_ports.length, last_seen: d.host.last_seen,
          };
          State.hosts.set(summary.id, summary);
          if (State.selectedHostId === summary.id) {
            State.hostDetail = d;
            renderHostDetail();
          }
          renderGraph(); renderTopbar();
        }).catch(() => {});
      }
      break;
    }
    case "port.opened":
    case "port.closed": {
      if (ev.host_id != null && State.selectedHostId === ev.host_id) {
        api.hostDetail(ev.host_id).then((d) => {
          State.hostDetail = d; renderHostDetail(); renderTopbar();
        }).catch(() => {});
      }
      // Also refresh the host's open_port_count in the summary map.
      if (ev.host_id != null) {
        api.hosts().then((hs) => {
          for (const h of hs) State.hosts.set(h.id, h);
          renderGraph();
        }).catch(() => {});
      }
      break;
    }
    case "scan.started": {
      State.scanning = true; renderTopbar(); break;
    }
    case "scan.ok": {
      State.scanning = false; renderTopbar(); break;
    }
    case "scan.error": {
      State.scanning = false; renderTopbar();
      if (!backfill) toast(`scan failed: ${ev.payload?.error || "unknown error"}`);
      break;
    }
    case "scan.skipped": {
      // No state change; just goes to the timeline.
      break;
    }
    default: {
      // Unknown kind — best-effort append to timeline only.
      break;
    }
  }
  appendEvent(ev);
}
```

- [ ] **Step 2: Manual smoke**

Restart `sudo uv run netmap up --no-open`. Open the browser. With DevTools network tab open, confirm:
- `GET /api/v1/stream` opens and stays in "pending" (SSE long-lived connection).
- Topbar `live` indicator is green.
- Open another shell, `curl -X POST http://127.0.0.1:8765/api/v1/scans -d '{"mode":"default"}' -H content-type:application/json`.
- The topbar flips to "scanning…", new hosts appear within ~30 s, then it flips back.
- Stop the server (Ctrl-C). The browser's `live` indicator flips to yellow "reconnecting…". Restart the server → it goes back to green.

- [ ] **Step 3: Commit**

```bash
git add src/netmap/ui/app.js
git commit -m "feat(ui): app.js section 3 — SSE client with backoff reconnect + per-kind reducer"
```

---

### Task 26 — `ui/app.js` — Section 4: host detail panel + timeline

**Files:**
- Modify: `src/netmap/ui/app.js`

Replaces the final two placeholders (`renderHostDetail`, `appendEvent`). The host-detail panel renders Overview / Open ports / IP history / Recent events / Notes (the last two disabled with a "M3" tooltip). The timeline renders the most recent ~200 events.

- [ ] **Step 1: Replace the section-4 placeholder block**

In `src/netmap/ui/app.js`, find:
```
// -------------------- section 4: host detail + timeline (Task 26) --------------------
function renderHostDetail() {}
function appendEvent(_ev) {}
```
Replace those three lines with:

```javascript
// -------------------- section 4: host detail + timeline --------------------

function _iconNode(name, color, size = 24) {
  const uri = iconDataUri(name, color);
  const img = el("img", {
    src: uri, alt: "", width: String(size), height: String(size),
    class: "host-icon",
  });
  return img;
}

function renderHostDetail() {
  const empty = $("#detailEmpty");
  const body = $("#detailBody");
  if (!State.hostDetail) {
    empty.hidden = false;
    body.hidden = true;
    body.replaceChildren();
    return;
  }
  empty.hidden = true;
  body.hidden = false;

  const d = State.hostDetail;
  const head = el("div", { class: "host-head" },
    _iconNode(iconForDevice(d.host.device_type), getCss("--text"), 28),
    el("div", { class: "host-meta" },
      el("div", { class: "ip" }, d.host.hostname || d.host.primary_ip),
      el("div", { class: "mac" }, d.host.mac || "no mac"),
      el("div", { class: "vendor" }, d.host.vendor || "vendor unknown"),
    ),
  );

  const overview = _section("overview", false, [
    _kv("ip", d.host.primary_ip),
    _kv("device", d.host.device_type || "unknown"),
    _kv("os", d.host.os_detail || d.host.os_family || "—"),
    _kv("trusted", d.host.trusted ? "yes" : "no"),
    _kv("last seen", fmtRelative(d.host.last_seen)),
  ]);

  const portsSection = _section(
    `open ports [${d.open_ports.length}]`,
    false,
    d.open_ports.length
      ? d.open_ports.map((p) => {
          const r = portRisk(p.protocol, p.number);
          return el("div", { class: "port-row " + r.tier },
            el("span", { class: "rl" }, r.label[0]),
            el("span", {}, `${p.number}/${p.protocol}`),
            el("span", { class: "rl" }, r.label),
            el("span", {}, p.service ? `${p.service}${p.version ? " · " + p.version : ""}` : ""),
          );
        })
      : [el("div", { class: "detail-disabled-note" }, "no open ports observed")],
  );

  const history = _section(
    `ip history [${d.ip_history.length}]`,
    true,
    d.ip_history.length
      ? d.ip_history.map((row) =>
          el("div", { class: "ip-history-row" },
            el("span", {}, row.ip),
            el("span", { class: "meta" },
              `${fmtRelative(row.first_seen)} → ${fmtRelative(row.last_seen)}`),
          ))
      : [el("div", { class: "detail-disabled-note" }, "single IP only")],
  );

  const events = _section(
    `recent events [${d.recent_events.length}]`,
    true,
    d.recent_events.length
      ? d.recent_events.slice(0, 25).map((ev) =>
          el("div", { class: "event-row" },
            el("span", { class: "ts" }, fmtTime(ev.ts)),
            el("span", {}, ev.kind),
            el("span", { class: "ts" }, ev.payload ? JSON.stringify(ev.payload) : ""),
          ))
      : [el("div", { class: "detail-disabled-note" }, "no events recorded")],
  );

  const notes = _section("notes", true, [
    el("div", { class: "detail-disabled-note",
                title: "trust / notes / device_type override ship in M3" },
      "trust toggle + notes — [M3]"),
  ]);

  body.replaceChildren(head, overview, portsSection, history, events, notes);
}

function _section(title, collapsed, children) {
  const section = el("section",
    { class: "detail-section", dataset: { collapsed: collapsed ? "true" : "false" } });
  const head = el("h3", { class: "section-h" }, title);
  head.addEventListener("click", () => {
    const next = section.dataset.collapsed === "true" ? "false" : "true";
    section.dataset.collapsed = next;
  });
  section.appendChild(head);
  section.appendChild(el("div", { class: "section-body" }, ...children));
  return section;
}

function _kv(k, v) {
  return el("div", { class: "event-row" },
    el("span", { class: "ts" }, k),
    el("span", {}, String(v)),
  );
}

function appendEvent(ev) {
  State.events.unshift(ev);
  if (State.events.length > TIMELINE_CAP) State.events.length = TIMELINE_CAP;
  renderTimeline();
  // Mirror to the screen-reader-accessible table.
  _renderSrTable();
}

function renderTimeline() {
  const list = $("#timelineList");
  if (!list) return;
  const items = State.events.slice(0, 80).map((ev) =>
    el("li", {},
      el("span", { class: "ts" }, fmtTime(ev.ts)),
      el("span", {
        class: "kind" + (ev.kind === "scan.error" || ev.kind === "host.new" ? " risk" : "")
      }, ev.kind),
      el("span", { class: "detail-text" },
        ev.payload ? JSON.stringify(ev.payload) : ""),
    ),
  );
  list.replaceChildren(...items);
}

function _renderSrTable() {
  const table = document.getElementById("srHostTable");
  if (!table) return;
  const rows = [el("tr", {},
    el("th", {}, "ip"), el("th", {}, "host"),
    el("th", {}, "ports"), el("th", {}, "last seen"),
  )];
  for (const h of State.hosts.values()) {
    rows.push(el("tr", {},
      el("td", {}, h.primary_ip),
      el("td", {}, h.hostname || ""),
      el("td", {}, String(h.open_port_count)),
      el("td", {}, fmtRelative(h.last_seen)),
    ));
  }
  table.replaceChildren(...rows);
}
```

- [ ] **Step 2: Manual smoke**

Restart the server, wait for hosts to populate (or trigger via curl), click a host node.

Expected:
- Right panel shows the host icon + hostname/IP/MAC/vendor block.
- "overview" + "open ports" sections expanded.
- Open ports show colored risk badges (red for 445/3389, yellow for 22, green for 80/443).
- Clicking "ip history" / "recent events" / "notes" toggles expand.
- Bottom timeline strip shows recent events (newest first), updates live as scans run.
- DevTools console: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/netmap/ui/app.js
git commit -m "feat(ui): app.js section 4 — host detail panel + live timeline"
```

---

## Phase 6 — Integration + polish (Tasks 27-28)

### Task 27 — Integration smoke test for `netmap up`

**Files:**
- Create: `tests/integration/test_up_smoke.py`

Spawns `netmap up` as a subprocess, polls the API until the first scan completes, opens an SSE stream, triggers a scan, asserts the SSE delivers a `host.new` for `127.0.0.1`, sends SIGINT, asserts clean exit. Mirrors M1's smoke pattern — skipped on CI if `nmap` is missing or not running as root.

- [ ] **Step 1: Write the test**

`tests/integration/test_up_smoke.py`:
```python
"""End-to-end smoke for `netmap up`. Skipped unless nmap is on PATH and the
test process can scan 127.0.0.1 (i.e. root or CAP_NET_RAW)."""
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from contextlib import closing

import httpx
import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("nmap") is None, reason="nmap binary not on PATH",
    ),
    pytest.mark.skipif(
        os.geteuid() != 0, reason="must run as root for raw sockets",
    ),
]


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for(predicate, *, timeout=20, interval=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


@pytest.fixture
def netmap_proc(tmp_path):
    port = _free_port()
    db = tmp_path / "state.db"
    config = tmp_path / "config.toml"
    # Stub config that allows loopback scan via override flag-like mechanism:
    # we wire safety policy by configuring max_target_hosts to allow /32 and
    # we'll POST against 127.0.0.1/32 with the routes' `confirm=true` arg.
    # But default deny_cidrs blocks 127.0.0.0/8 — for the smoke we strip it.
    config.write_text(
        "[server]\nbind = \"127.0.0.1\"\nport = " + str(port) + "\n"
        "[safety]\ndeny_cidrs = []\n"
    )
    env = {**os.environ}
    proc = subprocess.Popen(
        [sys.executable, "-m", "netmap", "up",
         "--db", str(db), "--config", str(config), "--no-open"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
    )
    base = f"http://127.0.0.1:{port}"

    def ready():
        try:
            httpx.get(base + "/api/v1/subnets", timeout=1)
            return True
        except Exception:
            return False

    if not _wait_for(ready, timeout=20):
        proc.kill()
        raise RuntimeError(
            "netmap up never opened the API:\n" + proc.stderr.read().decode()
        )
    yield base, proc
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_post_scan_triggers_host_new_event_for_loopback(netmap_proc):
    base, proc = netmap_proc

    # Open SSE; collect kinds for 30s while we trigger a scan against 127.0.0.1/32.
    seen_kinds: list[str] = []
    with httpx.stream("GET", base + "/api/v1/stream", timeout=30) as resp:
        r = httpx.post(
            base + "/api/v1/scans",
            json={"mode": "default", "targets": ["127.0.0.1/32"]},
            timeout=5,
        )
        assert r.status_code == 200, r.text

        deadline = time.monotonic() + 30
        for line in resp.iter_lines():
            if time.monotonic() > deadline:
                break
            if not line.startswith("data:"):
                continue
            payload = json.loads(line[len("data:"):].strip())
            seen_kinds.append(payload["kind"])
            if "host.new" in seen_kinds and "scan.ok" in seen_kinds:
                break

    assert "scan.started" in seen_kinds
    assert "scan.ok" in seen_kinds
    assert "host.new" in seen_kinds


def test_sigint_exits_cleanly(netmap_proc):
    _base, proc = netmap_proc
    proc.send_signal(signal.SIGINT)
    try:
        rc = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        pytest.fail("netmap up did not exit within 5s of SIGINT")
    assert rc == 0
```

- [ ] **Step 2: Run the integration test**

Run (as root, with `nmap` installed):
```bash
sudo -E env "PATH=$PATH" uv run pytest tests/integration/test_up_smoke.py -v -m integration
```
Expected: both tests PASS. On a CI machine without root or nmap, both are skipped with a clear reason.

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_up_smoke.py
git commit -m "test(integration): smoke `netmap up` — SSE delivers host.new, SIGINT exits cleanly"
```

---

### Task 28 — Final code-health sweep + README + manual smoke checklist

**Files:**
- Run: `ruff check`, `ruff format` (if applicable)
- Run: `uv run pytest -m "not integration"`
- Modify: `README.md`

- [ ] **Step 1: Run ruff and fix anything it flags**

Run: `uv run ruff check src tests`
Expected: clean output (no findings). If anything is flagged, fix it in a focused commit before proceeding.

- [ ] **Step 2: Run the full unit + API test suite**

Run: `uv run pytest -m "not integration" -q`
Expected: all green. Rough total: ~140+ tests passing (M1's 99 + M2's additions).

- [ ] **Step 3: Update `README.md` with the M2 "what's new" section + manual smoke checklist**

Read the current `README.md`. After the M1 quick-start section, add (or update) an M2 section:

```markdown
## M2 — `netmap up` (web UI + foreground scan loop)

Start the foreground web app:

```bash
sudo uv run netmap up
```

Open http://127.0.0.1:8765 in a browser. The UI auto-detects your local subnet,
runs a discover scan every 60s and a deeper sweep every 10 minutes, and updates
live over Server-Sent Events. Ctrl-C stops the process cleanly.

Override the target:

```bash
sudo uv run netmap up --target 192.168.7.0/24
```

### M2 manual smoke checklist

After making any UI-affecting change, run through this list:

1. `sudo uv run netmap up` on a real LAN.
2. Browser loads `http://127.0.0.1:8765` with no console errors.
3. First discover populates hosts within ~60s; the graph appears.
4. Clicking a host shows the right-panel detail with open ports.
5. "scan now" triggers a default scan; the timeline updates live.
6. Disconnect Wi-Fi for 30s and reconnect — the live indicator flips yellow
   then back to green; the catch-up fetch restores any missed events.
7. DevTools network tab shows `/api/v1/stream` in "pending" the whole time
   (one persistent SSE connection).
8. `prefers-reduced-motion: reduce` (in DevTools rendering panel) disables
   the cursor blink, the live pulse, and the CRT scan-lines.
```

- [ ] **Step 4: Dispatch a final whole-PR code-health review**

Per the maintainer's agent-split policy (Opus for reflection-heavy reviews),
spawn an Opus subagent to read every file changed since the M1 merge base
(`git diff origin/main...HEAD --stat` lists them) and check for:
- code-quality issues (unused vars, dead branches, magic numbers in routes/loop).
- spec drift: walk the M2 spec's API table (§10.1), event-kinds table (§7.1),
  reducer table (§12.6), and confirm each row maps to code.
- security: confirm no scanner entry path bypasses `validate_target`; confirm
  SSE handler unsubscribes on disconnect; confirm the `in_flight` set is
  cleaned up in every termination branch of `_run_scan_work`.

Apply any feedback as one or more small follow-up commits.

- [ ] **Step 5: Commit + push**

```bash
git add README.md
git commit -m "docs(readme): add M2 quick-start + manual smoke checklist"
git push origin main
```

---

## Self-review

Coverage check (spec sections → tasks):

- §5 Architecture / lifecycle — Task 14 (lifespan), Task 20 (CLI), Task 11/12 (scan loop), Task 18 (SSE).
- §6 Module layout — every new module has its own task; the wheel `force-include` lives in Task 1.
- §7 Schema + new event kinds — Task 11 emits all four `scan.*` kinds; UI reducer (Task 25) handles them.
- §8 Scan loop — Tasks 11 (`maybe_run`) + 12 (`scan_loop`) + tests cover cadence, in-flight skip, exception containment.
- §9 Subnet bootstrap — Tasks 8 (parsers) + 9 (run integrator).
- §10 Web API — Tasks 15-17 cover every row of the §10.1 endpoint table; Task 18 covers `/stream`; Task 19 covers `/` + `/ui/*`.
- §11 SSE — Task 18 (server) + Task 25 (client backoff + catch-up).
- §12 Frontend — Tasks 21-26 cover index.html, styles.css, app.js sections; visual identity baked into Task 22; icons inlined in Task 21.
- §13 Privilege — Task 7 (with all three gates: caps, nmap, bind).
- §14 Configuration — Task 6 wires host-timeout config through `NmapScanner`; CLI in Task 20 honors `--bind` / `--port` overrides.
- §15 Error handling — covered across Tasks 7, 9, 11, 17, 14 (lifespan shutdown timeout), 25 (browser reconnect).
- §16 Testing — every unit / API / integration test file from §16.1-§16.3 lands in its own task; §16.4 manual smoke captured in Task 28's checklist.
- §17 Operational details — `netmap up` CLI flags (Task 20), default port + bind, signal handling (uvicorn's), DB location (Task 20's `--db` default).

Type / signature consistency:
- `maybe_run(*, mode, targets, db, bus, cfg, in_flight, source, scanners_for_mode=...)` — same in Task 11 (definition), Task 17 (call site), Task 12 (call site).
- `Storage.list_subnets() -> list[Subnet]` — Task 2 defines; Tasks 9, 12, 16, 17 call.
- `Storage.list_host_summaries(*, subnet_id, q) -> list[dict]` — Task 3 defines; Task 15 calls.
- `Storage.list_scans(*, status, since, limit) -> list[Scan]` — Task 5 defines; Task 16 calls.
- `Storage.get_host(id) -> Host | None` — Task 4 defines; Task 15 calls.
- `Storage.list_recent_events(*, host_id, limit) -> list[Event]` — Task 4 defines; Task 15 calls.
- `AsyncBus.subscribe() / publish() / unsubscribe()` — Task 10 defines; Tasks 11, 18 call.
- `create_app(*, cfg, db, bus, in_flight, stop)` — Task 14 defines; Task 20 calls via `server.app.run()`.
- `privilege.check_or_exit(cfg)` — Task 7 defines; Task 14 calls via `run()`.
- `subnet_bootstrap.run(db, *, override, policy=None)` — Task 8 defines; Task 14 calls via `run()`.

No placeholders. No "TBD" or "similar to Task N" — every step has full code or an exact command.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-25-netmap-m2-web-ui.md`.

**Recommendation:** Subagent-Driven execution with the maintainer's model-split policy:
- **Opus (high/xhigh) implementers** for: T7 (privilege), T11 (maybe_run), T12 (scan_loop), T14 (lifespan), T17 (POST /scans), T18 (SSE), T24 (Cytoscape graph), T25 (SSE client reducer).
- **Sonnet implementers** for: T1-T6, T8-T10, T13, T15, T16, T19, T20, T21-T23, T26, T27.
- **Sonnet** spec reviewer + code-quality reviewer after every task.
- **Opus** final whole-PR code-health pass (T28 step 4) once all tasks are merged into the working branch.





