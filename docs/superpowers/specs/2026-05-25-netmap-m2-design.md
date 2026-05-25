# net-map M2 — Web UI + Foreground Scan Loop · Design Spec

**Status:** Draft (awaiting user approval)
**Date:** 2026-05-25
**Author:** Aymen
**Builds on:** [`2026-05-25-netmap-design.md`](2026-05-25-netmap-design.md) (the v1 spec) and [`2026-05-25-netmap-m1-cli-scanner.md`](../plans/2026-05-25-netmap-m1-cli-scanner.md) (the shipped M1).

---

## 1. Summary

M2 turns the M1 CLI scanner into a foreground web app. A single command — `sudo netmap up` — starts a FastAPI server bound to `127.0.0.1:8765`, kicks off a foreground asyncio scan loop, and serves a single-page web UI that visualizes the topology and updates live over Server-Sent Events.

Operator workflow: `sudo netmap up` → browser at `http://localhost:8765` → subnet-grouped Cytoscape graph with device-type icons, accordion host-detail panel, live event timeline. The loop scans every 60 s (`discover`) plus a deeper sweep every 10 minutes (`default`). Ctrl-C stops everything cleanly. No daemon, no cron, no systemd.

## 2. Goals

- Ship `netmap up` as the always-on (while-running) face of the project.
- Auto-detect the host's local subnet so a fresh install requires zero configuration.
- Render the topology as a subnet-grouped graph with **device-type icons**, not colored shapes — identity comes from the icon, color encodes state and risk.
- Serve a polished "Terminal Console" visual identity: pure black canvas, Geist Mono throughout, phosphor-green accents.
- Update the UI live via SSE — no polling — and survive transient network blips with client reconnect.
- Expose a minimum REST API the UI needs (5 GETs + 1 POST + 1 SSE), no mutation endpoints beyond `POST /scans`.
- Preserve all M1 invariants: M1's `netmap scan / db / config` commands continue to work; the schema is unchanged; safety validation is the single chokepoint for every scanner entry point including the new web-triggered ones.

## 3. Non-goals (M2)

Explicit deferrals to M3:

- Passive sniffer (scapy DHCP/mDNS/LLDP/CDP capture thread).
- Gateway traversal + `POST /api/v1/subnets/discover`.
- All mutation endpoints beyond `POST /scans`: `PATCH /hosts/{id}` (trust / notes / device_type override), `POST/PATCH/DELETE /subnets`, `PATCH /config`.
- Edges table population. M1's correlation already drops `EdgeFact`s; M2 makes no edges except an implicit gateway→host edge synthesized at render time from subnet membership.
- Retention GC, `netmap diff`, `netmap export`, `netmap update-oui`, `netmap config set`, `netmap subnets ...`.
- Non-loopback bind (`bind != 127.0.0.1`). The bearer-token auth path lands in M3; M2 explicitly refuses to start with a non-loopback bind.
- Layout switcher in the UI (force-directed / hierarchical alternates) — subnet-grouped only in M2.
- Frontend automated tests (Playwright, etc.).

## 4. Use case driving the defaults

> "Run `sudo netmap up` on my laptop, open the browser, and see what's on this network — live. When I plug into a different network it auto-detects and starts scanning that one instead."

This anchors: foreground process (Ctrl-C stops it), no daemon, auto-detect on boot, instant SSE updates so the UI feels alive, single-binary deployment (CDN-loaded frontend, no node toolchain).

---

## 5. Architecture

Single Python process. Five subsystems, all coordinated by a FastAPI `lifespan` context manager.

```
                       ┌──────────────────────────────────────┐
                       │  CLI (Typer) — `netmap up`           │
                       └─────────────┬────────────────────────┘
                                     │ launches with sudo
                       ┌─────────────▼────────────────────────┐
                       │  FastAPI lifespan                    │
                       │  startup:                            │
                       │    privilege.check_or_exit()         │
                       │    Storage(...)                      │
                       │    subnet_bootstrap.run(...)         │
                       │    AsyncBus()                        │
                       │    asyncio.create_task(scan_loop)    │
                       │    uvicorn binds 127.0.0.1:8765      │
                       │  shutdown: stop.set(); drain; close  │
                       └──────┬────────────────────┬──────────┘
                              │                    │
              ┌───────────────▼──────────┐  ┌──────▼───────────────────┐
              │  scanner/loop.py         │  │  server/                 │
              │  scan_loop(db,bus,stop)  │  │    app.py routes.py      │
              │  - discover every 60s    │  │    events.py             │
              │  - default every 600s    │  │  /api/v1/*               │
              │  - in-flight set guard   │  │  /api/v1/stream (SSE)    │
              │  - reuses correlate()    │  │  serves /ui/* static     │
              └────────────┬─────────────┘  └─────┬────────────────────┘
                           │ writes              │ reads
                  ┌────────▼────────────────────▼─────────┐
                  │  Storage (M1, schema unchanged)       │
                  └───────────────────────────────────────┘
```

### 5.1 Lifecycle

1. `sudo netmap up` → Typer parses flags → calls `server.app.run(...)`.
2. `lifespan` startup runs (synchronously, before the server binds):
   - `privilege.check_or_exit()` — root or `CAP_NET_RAW + CAP_NET_ADMIN`; nmap binary on PATH; bind is loopback (in M2). Exits 1 with a friendly fix instruction on any failure.
   - `Storage(cfg.db_path)` — opens the file at `~/.netmap/state.db` (already M1 behavior).
   - `subnet_bootstrap.run(db, override=cli.targets)` — inserts the local CIDR if no `subnet` rows exist OR `--target` was passed (override path replaces auto-detect).
   - `bus = AsyncBus()` — in-process event broadcaster.
   - `loop_task = asyncio.create_task(scan_loop(db, bus, stop, cfg))`.
3. uvicorn binds and starts serving.
4. The browser opens to `/`, fetches initial state, opens the SSE stream.
5. On SIGINT/SIGTERM: `stop.set()` → scan loop exits at next checkpoint → in-flight nmap subprocesses sent `SIGTERM` → loop task awaited with `wait_for(timeout=3)` → DB closed → uvicorn drains → process exits.

### 5.2 Threading model (delta from M1)

| Thread / task | Purpose |
|---|---|
| Main thread, asyncio loop | FastAPI, scan loop, correlation, DB writes, event bus, SSE subscribers |
| Subprocesses (`asyncio.create_subprocess_exec`) | nmap invocations (M1, unchanged) |
| `asyncio.to_thread` workers | scapy ARP `srp` (M1, unchanged) |

No new threads in M2. Passive sniffer (which needs its own thread) is M3.

### 5.3 Concurrency rules

- **One discover scan and one default scan at most in flight at any time.** Loop checks an `in_flight: set[tuple[str, str]]` of `(mode, target_signature)` before dispatch. Collision writes a `scan` row with `status='skipped'` and a `scan.skipped` event is published.
- `Storage` is shared across the loop and all API handlers. SQLite WAL + `check_same_thread=False` (set in M1) makes this safe. We do not introduce a lock; SQLite serializes writes internally.
- The `AsyncBus` uses `asyncio.Queue(maxsize=200)` per subscriber. Slow consumers drop oldest events (server-side) — never block the publisher. The client treats lost events as a signal to refetch `/hosts` + `/events?since=<last_ts>` on next connect.

---

## 6. Module layout (additions)

```
src/netmap/
├── cli.py                       # adds `up` command alongside scan/db/config
├── server/
│   ├── __init__.py
│   ├── app.py                   # FastAPI app + lifespan
│   ├── routes.py                # REST endpoints
│   ├── events.py                # AsyncBus, EventOut serialization
│   ├── schemas.py               # response DTOs (HostSummary, HostDetail, etc.)
│   ├── subnet_bootstrap.py      # detect local CIDR via `ip route`
│   └── privilege.py             # startup capability + nmap binary checks
├── scanner/
│   └── loop.py                  # scan_loop async coroutine
└── ui/
    ├── index.html               # shell, CDN <link>/<script>, inlined <symbol> defs for device icons
    ├── styles.css               # palette tokens, layout, components
    └── app.js                   # Cytoscape config, SSE client, state, DOM glue
tests/
├── unit/
│   ├── test_loop.py
│   ├── test_events_bus.py
│   ├── test_subnet_bootstrap.py
│   └── test_privilege.py
├── api/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_hosts.py
│   ├── test_scans.py
│   ├── test_events.py
│   ├── test_subnets.py
│   ├── test_sse.py
│   └── test_static.py
└── integration/
    └── test_up_smoke.py         # spawns `netmap up`, drives via HTTP
```

**Boundaries:** `scanner/loop.py` is the only new module that holds state across iterations. Everything else is request/handler or pure function. Static `ui/` files are bundled into the wheel via the existing `pyproject.toml` `[tool.hatch.build.targets.wheel.force-include]` mechanism — same pattern as `src/netmap/data/` for OUI data.

---

## 7. Data model

### 7.1 Schema additions

**None.** M1's SQLite schema is sufficient. M2 emits three new `event.kind` values into the existing `event` table:

| New `kind`        | Payload                                          | Source |
|-------------------|--------------------------------------------------|--------|
| `scan.started`    | `{mode, target}`                                 | `_run_one` right after `start_scan` |
| `scan.ok`         | `{hosts_seen, duration_s}`                       | `_run_one` right before `finish_scan(status='ok')` |
| `scan.error`      | `{error, mode, target}`                          | `_run_one` exception handler |
| `scan.skipped`    | `{reason, mode, target}` (e.g. `"already running"`) | in-flight guard |

The `event.kind` column is intentionally free-text (M1 design choice; ROADMAP extension point), so no schema migration. Existing UI consumers ignore unknown kinds gracefully.

### 7.2 Response DTOs (`server/schemas.py`)

Reuse M1 DTOs where possible. New types are presentation-only, not persisted.

```python
class HostSummary(BaseModel):       # GET /hosts list item
    id: int
    mac: str | None
    primary_ip: str
    hostname: str | None
    vendor: str | None
    device_type: str | None
    trusted: bool
    open_port_count: int            # computed in SQL via LEFT JOIN port
    last_seen: datetime

class HostDetail(BaseModel):        # GET /hosts/{id}
    host: Host                      # M1 DTO
    open_ports: list[Port]          # state='open' only
    ip_history: list[HostIp]
    edges: list[Edge]               # empty in M2
    recent_events: list[Event]      # last 50

class HostIp(BaseModel):
    ip: str
    first_seen: datetime
    last_seen: datetime

class ScanRequest(BaseModel):       # POST /scans body
    mode: ScanMode
    targets: list[str] | None = None
    confirm: bool = False

class ScanResponse(BaseModel):      # POST /scans response
    scan_id: int
    accepted_targets: list[str]
```

`GET /subnets`, `/scans`, `/events` return M1 DTOs directly (`list[Subnet]`, `list[Scan]`, `list[Event]`).

---

## 8. Scan loop

`scanner/loop.py`:

```python
async def scan_loop(db: Storage, bus: AsyncBus, stop: asyncio.Event,
                    cfg: Config) -> None:
    last_default = 0.0
    in_flight: set[tuple[str, str]] = set()
    while not stop.is_set():
        await _maybe_run("discover", db, bus, cfg, in_flight)
        if time.monotonic() - last_default > cfg.scan.default_scan_interval_s:
            asyncio.create_task(_maybe_run("default", db, bus, cfg, in_flight))
            last_default = time.monotonic()
        try:
            await asyncio.wait_for(stop.wait(), timeout=cfg.scan.interval_s)
        except asyncio.TimeoutError:
            pass
```

`_maybe_run(mode, ...)`:

1. Build the target list: every `subnet` row with `enabled=1`.
2. For each target, run `validate_target(t, policy)` (M1 safety). Reject early; emit `scan.error` per rejected target.
3. Compose a `target_signature` (sorted CIDR list, comma-joined). If `(mode, signature) in in_flight`, write `scan` row with `status='skipped'`, publish `scan.skipped`, return.
4. Add to `in_flight`. Open a `scan` row with `status='running'`, publish `scan.started`.
5. Instantiate `NmapScanner()`, `ArpScanner(iface=cfg.scan.iface)`. For each target, run both async generators (for `discover`, ARP is sufficient on local subnets; nmap discover sweep covers the rest).
6. Pass facts to `correlate(facts, db, scan_id, now=..., observed_subnets=...)`. `observed_subnets` is the validated target list **only when `mode in (DEFAULT, DEEP)`**; empty for `discover` (port-closure semantics).
7. Each event returned by `correlate()` is published on the bus.
8. Finalize the `scan` row with `status='ok'`, publish `scan.ok`.
9. Remove from `in_flight`.

On exception anywhere in steps 4-8: emit `scan.error`, finalize `scan` row with `status='error'`, remove from `in_flight`. The loop never crashes.

---

## 9. Subnet bootstrap

`server/subnet_bootstrap.py` exports `run(db, override: list[str] | None) -> None`:

1. If `override` is non-empty: for each CIDR, `validate_target(...)` (with `override_deny=False`); insert as `subnet(source='config', enabled=1, hop_distance=0, first_seen=now)`. Return.
2. Else, if `db.list_subnets()` is non-empty: no-op (operator already configured CIDRs).
3. Else: parse `ip route show default` and `ip -o -f inet addr show` (subprocess) to find the host's primary interface and its `/N` CIDR.
4. Insert the detected CIDR as `subnet(source='config', enabled=1, hop_distance=0, first_seen=now)`. Log "auto-detected <CIDR> on <iface>".
5. If detection fails (no default route, parse error): log a warning, insert nothing. The loop will run with an empty enabled-subnet set; the UI shows the "waiting for `--target`" empty state. Operator can restart with `--target` or wait for M3's `subnets add`.

`ip route` parsing is a pure function over its text output — fully unit-testable against fixture strings.

---

## 10. Web API

All endpoints under `/api/v1`. Default bind `127.0.0.1:8765`. No auth in M2.

### 10.1 Endpoint table

| Method | Path                       | Purpose                                                      |
|--------|----------------------------|--------------------------------------------------------------|
| GET    | `/api/v1/hosts`            | `list[HostSummary]`. Filters: `?subnet=<id>`, `?q=<search>`. |
| GET    | `/api/v1/hosts/{id}`       | `HostDetail`. 404 if unknown.                                |
| GET    | `/api/v1/subnets`          | `list[Subnet]` (read-only in M2).                            |
| GET    | `/api/v1/scans`            | `list[Scan]`. Filters: `?status=`, `?since=`, `?limit=` (default 50). |
| GET    | `/api/v1/events`           | `list[Event]`. Filters: `?since=`, `?host_id=`, `?kind=`, `?limit=` (default 500). |
| POST   | `/api/v1/scans`            | `ScanRequest` → `ScanResponse`. Triggers `_maybe_run` synchronously; returns once the scan row is created and the background task is dispatched (not when the scan completes). |
| GET    | `/api/v1/stream`           | SSE — see §11.                                               |
| GET    | `/`                        | Serves `ui/index.html`.                                      |
| GET    | `/ui/{path:path}`          | Static asset (CSS/JS/SVG/etc.).                              |

### 10.2 Error responses

FastAPI's `{"detail": ...}` shape.

| Status | When |
|---|---|
| 400 | Malformed request body (bad JSON, missing required field). |
| 404 | Unknown id for `/hosts/{id}`, `/scans/{id}` (future), or `/subnets/{id}` (future). |
| 409 | `POST /scans` target rejected by `validate_target` (reason in `detail`), or same `(mode, target_signature)` already in-flight. |
| 422 | Pydantic validation failure (auto). |
| 500 | DB / subprocess / unhandled exception. Logged with traceback. |

---

## 11. Server-Sent Events

### 11.1 Endpoint contract

```
GET /api/v1/stream
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-store
X-Accel-Buffering: no
Connection: keep-alive

: connected

data: {"id":1234,"ts":"2026-05-25T14:32:11.408Z","scan_id":87,"host_id":42,"kind":"port.opened","payload":{...}}

: ping             ← every 30s as keepalive

data: {...}
```

- Payload = `Event` DTO from M1, JSON-serialized.
- `sse-starlette`'s `EventSourceResponse` handles framing and the periodic ping.
- Per-connection `bus.subscribe()` returns a fresh `asyncio.Queue(maxsize=200)`. Handler `await queue.get()` in a loop, yields each event.
- On client disconnect: `EventSourceResponse` triggers cleanup → handler removes the queue from the bus.

### 11.2 Client reconnect contract

- Client starts a single `EventSource` on bootstrap.
- On `onerror`: close current connection, reconnect with exponential backoff (1 s → 30 s cap), reset to 1 s on a successful `onopen`.
- On successful reconnect: refetch `/api/v1/hosts` (full list) and `/api/v1/events?since=<last_event_ts>` (catch up timeline). This makes lost events recoverable without forcing exactly-once delivery on the server.
- Backlog: M2 does **not** replay missed events on reconnect server-side. The catch-up fetch is the recovery mechanism.

---

## 12. Frontend

### 12.1 Tech stack

- **Vanilla HTML + CSS + JS.** No build step, no node, no bundler.
- **Cytoscape.js 3.30** via CDN (`unpkg.com/cytoscape@3.30.0`).
- **cose-bilkent** layout plugin (CDN).
- **Geist Mono** via Google Fonts.
- **Lucide-style icons** inlined as one SVG sprite (`<symbol id="ic-router">…</symbol>` etc.) in `index.html`. The frontend never makes a separate request for icons.
- CDN URLs are version-pinned, never `@latest`.

### 12.2 File layout

```
ui/
├── index.html      ~120 lines  — shell, CDN <link>/<script>, root containers, inlined SVG <symbol> defs for every device icon
├── styles.css      ~300 lines  — :root palette tokens, layout grid, component styles
└── app.js          ~600 lines  — state, SSE client, Cytoscape config, DOM render functions
```

No build step. The icon set lives as a `<svg><defs>…<symbol id="ic-router">…</symbol>…</defs></svg>` block at the top of `index.html` (≈40 lines, ~2 KB). Editing the icons means editing `index.html`. If the set grows beyond ~20 icons we'll move them to a separate `icons.svg` and reference them via cross-document `<use href="/ui/icons.svg#ic-router">` — but that's a future concern, not M2's.

### 12.3 Visual identity — Terminal Console

Frozen choices from M2 brainstorming:

**Palette (CSS custom properties):**
```
--bg:         #020617    (background)
--surface:    #0B1220
--surface-2:  #0F1A2E
--border:     #1F2937
--text:       #E5E7EB
--text-muted: #6B7280
--accent:     #22C55E    (phosphor green — used for live indicators, "scan now" CTA, gateway edges)
--risk-red:   #F87171    (high: SMB/RDP/Telnet/unauth DB ports)
--risk-yel:   #FBBF24    (elev: SSH, admin UIs 9000-9999)
--risk-grn:   #22C55E    (normal: HTTP/HTTPS family)
--risk-gray:  #6B7280    (info: mDNS, broadcast, unclassified)
```

**Type:** Geist Mono throughout. Weights 400 / 500 / 600 / 700. Numeric / identifier alignment matters more than expressive typography — monospace handles both.

**Iconography:** Lucide-style stroke icons (1.6 stroke width). One icon per device type — router, server, NAS, laptop, phone, printer, AP (wifi), camera, IoT (chip), unknown (dashed `?`). Color encodes state, never identity.

**Affordances:** single-pixel borders, no rounded corners on the outer frame (terminal feel), 8 px grid rhythm. The brand wordmark has a blinking `▌` cursor prefix. A subtle horizontal-line texture on the graph canvas evokes CRT scan-lines (respects `prefers-reduced-motion`).

### 12.4 Components

- **Topbar (40 px)**: brand · breadcrumb (`~/networks # discover · N hosts`) · KPI strip (hosts / ports / risk / last-scan age) · "scan now" CTA.
- **Left sidebar (180 px)**: subnets list with selection state · hop-distance display (read-only in M2; control lands in M3) · "discover via gw" placeholder marked M3.
- **Center: Cytoscape canvas** — compound parent nodes per CIDR (dashed border, label top-left), host nodes with device-type icon backgrounds + label below. Gateway node uses the router icon and bridges subnet boxes with a thicker accent-green edge.
- **Right panel (280 px)**: accordion host detail. Sections (Overview / Open ports / Edges / History / Notes) — Overview + Open ports expanded by default. Per-port risk row (border-left + tinted background). Trust toggle and notes textarea are rendered but disabled with "M3" tooltip.
- **Timeline strip (120 px, bottom)**: scrollable event feed, newest first. Each entry: `[ts] kind host detail`. Filterable by kind in M3; just-display in M2.

### 12.5 Application state (`State` object in `app.js`)

```
State.hosts             Map<id, HostSummary>
State.hostDetail        HostDetail | null  (loaded on selection)
State.subnets           Subnet[]
State.events            Event[]            (ring buffer, last 200)
State.selectedHostId    int | null
State.scanning          bool               (true between scan.started and scan.ok/error)
State.cy                CytoscapeInstance
State.sse               EventSource | null
State.lastEventTs       ISO timestamp      (for catch-up on reconnect)
```

### 12.6 SSE reducer table

| kind             | Reducer action |
|------------------|----------------|
| `host.new`       | `fetchHost(id)` → `State.hosts.set(...)` → `cy.add(node)`; appendTimeline; if id matches selection, reload host detail. |
| `host.gone`      | _(M2 doesn't emit yet — placeholder for M3)_ |
| `port.opened`    | If `selectedHostId === host_id`, invalidate detail → refetch. AppendTimeline. |
| `port.closed`    | Same as `port.opened`. |
| `ip.changed`     | `fetchHost(id)` → update graph node label + sidebar. AppendTimeline. |
| `scan.started`   | `State.scanning = true`; renderTopbar (pulse animation); appendTimeline. |
| `scan.ok`        | `State.scanning = false`; renderTopbar; appendTimeline. |
| `scan.error`     | `State.scanning = false`; renderTopbar; flashError toast; appendTimeline. |
| `scan.skipped`   | appendTimeline only (no UI state change). |
| _unknown kind_   | appendTimeline (best-effort) — forward-compat with M3+ events. |

### 12.7 Empty / loading / error states

- **First boot, no hosts yet:** graph area renders "waiting for first scan…" with target / mode / next-tick info. Replaced by the live graph when the first scan completes.
- **SSE disconnected:** topbar replaces the live indicator with `reconnecting…` until `EventSource.onopen` fires.
- **API call fails:** non-blocking toast at the bottom-right; auto-dismiss in 5 s; details on hover.

### 12.8 Accessibility baseline

- Visible focus rings on all interactive elements (`:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }`).
- Risk indicators are icon-shaped + text-labeled (never color-only). Each port row includes a short `high` / `elev` / `normal` label in addition to the colored left border.
- `prefers-reduced-motion`: disables pulse, fade, and the scan-line CRT texture.
- A hidden `<table>` mirrors `State.hosts` for screen-reader users — Cytoscape's canvas is not accessible by itself.
- Body text on `--bg` clears 4.5:1 contrast (Geist Mono `#E5E7EB` on `#020617` ≈ 15:1). Risk colors checked individually against `--bg`.

---

## 13. Privilege & safeguards

### 13.1 Startup check (`server/privilege.py`)

`check_or_exit(cfg: Config) -> None` runs before `Storage` is touched and before the server binds. It enforces:

1. `os.geteuid() == 0` **or** the process has `CAP_NET_RAW + CAP_NET_ADMIN` (read `/proc/self/status` `CapEff`).
2. `shutil.which("nmap")` returns a path.
3. `cfg.server.bind == "127.0.0.1"` (M2 refuses non-loopback bind — auth lands in M3).

On any failure, print a human-readable instruction (the exact text below) to stderr and `sys.exit(1)`:

```
net-map needs raw-socket privileges. Either:
  sudo netmap up
or grant once:
  sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

```
nmap binary not found on PATH. Install it:
  Debian/Ubuntu:  sudo apt install nmap
  Arch:           sudo pacman -S nmap
  macOS:          brew install nmap
```

```
non-loopback bind requires bearer-token auth, which lands in M3.
Set [server].bind = "127.0.0.1" or wait for M3.
```

### 13.2 Target validation reuse

Every scanner entry path (loop `_maybe_run`, `POST /api/v1/scans`) routes through M1's `validate_target` — no bypass.

### 13.3 Audit trail

Same as M1: every scan run writes a `scan` row; every event (including the new `scan.*` kinds) writes an `event` row. The UI timeline + a future `netmap diff` (M3) both read from these.

---

## 14. Configuration

No new config keys. M2 wires through fields already present in M1's `Config`:

| Key                                      | Used by | M1 status | M2 status |
|------------------------------------------|---------|-----------|-----------|
| `server.bind`                            | privilege.check_or_exit + uvicorn | reserved | active (loopback only) |
| `server.port`                            | uvicorn | reserved | active |
| `server.bearer_token`                    | — | reserved | reserved (M3) |
| `scan.interval_s`                        | scan_loop discover cadence | reserved | active |
| `scan.default_scan_interval_s`           | scan_loop default cadence | reserved | active |
| `scan.default_scan_host_timeout`         | nmap default flags | currently hardcoded in `_flags_for_mode` | **wired through** in M2 |
| `scan.deep_scan_host_timeout`            | nmap deep flags | currently hardcoded in `_flags_for_mode` | **wired through** in M2 |
| `scan.passive`                           | passive sniffer | reserved | reserved (M3) |
| `safety.*`                               | validate_target | active | active (unchanged) |
| `ui.default_layout` / `host_detail_layout` | UI | reserved | UI ignores; only subnet-grouped + accordion ship |
| `retention.*`                            | retention GC | reserved | reserved (M3) |
| `passive.*`                              | passive sniffer | reserved | reserved (M3) |

M2 also wires the host-timeout config keys through `NmapScanner` (one of the M1 review's "Important" follow-ups).

---

## 15. Error handling

A single principle: **the scan loop never crashes the process; the web server never silently swallows errors.**

| Failure | Caught by | Behavior |
|---|---|---|
| Not root / no caps | `privilege.check_or_exit` | Print fix, exit 1. |
| `nmap` missing | `privilege.check_or_exit` | Print install instruction, exit 1. |
| Subnet auto-detect fails | `subnet_bootstrap.run` | Log warning, continue with empty enabled set; UI shows "waiting for --target". |
| Port already in use | uvicorn raises `OSError` during startup | Catch, print "port 8765 in use; --port to override", exit 1. |
| `bind != 127.0.0.1` in M2 | `privilege.check_or_exit` | Print M3-deferral note, exit 1. |
| Scanner subprocess crash | `_maybe_run` try/except | Log traceback, `scan` row → `status='error'`, publish `scan.error`. Loop continues. |
| nmap exit nonzero | `NmapScanner.scan` raises (M1) | Same path as scanner crash. |
| `correlate()` raises | `_maybe_run` try/except | Same path. |
| sqlite write contention (`OperationalError`) | `_maybe_run` wraps DB writes | Retry 3× with exponential backoff (100/200/400 ms), then `scan.error`. |
| Bad config TOML | `load_config` raises (M1) | Caught in `lifespan` startup, print friendly error with file path, exit 1. |
| SSE client disconnect | `EventSourceResponse` cleanup | Server removes queue from bus; no-op otherwise. |
| Browser drops SSE | `EventSource.onerror` | Reconnect with backoff; refetch `/hosts` + `/events?since=last_ts`. |
| `POST /scans` for public CIDR without confirm | `validate_target` raises `SafetyError` | 409 with reason in `detail`. |
| `POST /scans` while same target running | `in_flight` check | 409 "scan already running on this target". |
| `lifespan` shutdown timeout | `asyncio.wait_for` raises | Log "scan loop did not stop cleanly; killing", cancel task, close DB, exit. |

---

## 16. Testing

### 16.1 Unit (pytest)

| File | Focus |
|---|---|
| `tests/unit/test_loop.py` | Mocked `ActiveScanner`s; assert cadence (discover ticks every N s of fake-clock; default kicks off at M s), in-flight skip, scan row state transitions, events published to bus, exception handling (scanner raises → scan.error + loop continues). |
| `tests/unit/test_events_bus.py` | Multiple subscribers, fanout, slow consumer drop-oldest behavior, subscribe/unsubscribe lifecycle. |
| `tests/unit/test_subnet_bootstrap.py` | Pure parse function over fixture `ip route` strings (Linux, "no default route", malformed). Override path inserts user-provided CIDR. No subprocess in tests. |
| `tests/unit/test_privilege.py` | Mock `os.geteuid`, `/proc/self/status` reader, `shutil.which("nmap")`. Each failure path → expected exit code + stderr text. |

### 16.2 API (FastAPI TestClient)

| File | Focus |
|---|---|
| `tests/api/conftest.py` | Fixture: a `TestClient` against an app with a `:memory:` Storage and a hand-driven `AsyncBus`. |
| `tests/api/test_hosts.py` | `GET /hosts` shape, `subnet` and `q` filters; `GET /hosts/{id}` includes ports/edges/recent_events; 404 on unknown id. |
| `tests/api/test_scans.py` | `GET /scans` paginated; `POST /scans` valid → 200 + scan_id; invalid CIDR → 409; same target in-flight → 409. |
| `tests/api/test_events.py` | `GET /events` filters by since/host_id/kind; pagination. |
| `tests/api/test_subnets.py` | `GET /subnets` returns rows; PATCH/POST/DELETE return 404 (not registered in M2). |
| `tests/api/test_sse.py` | Open SSE; publish synthetic event via DI'd bus; assert client receives it within 1 s. Keepalive comment lines don't break the JSON parser. |
| `tests/api/test_static.py` | `GET /` returns 200 with `<title>net-map</title>`; `GET /ui/styles.css` returns 200 with `text/css` and includes `Geist Mono`. |

### 16.3 Integration

`tests/integration/test_up_smoke.py` (extends M1's smoke test pattern):
1. `subprocess.Popen([sys.executable, "-m", "netmap", "up", "--bind", "127.0.0.1", "--port", <random>])` with `--allow-loopback`.
2. Poll `GET /api/v1/scans` until first scan appears.
3. Open SSE connection; trigger `POST /api/v1/scans` against `127.0.0.1/32` (loopback + nmap-aware mode).
4. Assert SSE delivers a `host.new` for `127.0.0.1` within 30 s.
5. Send SIGINT; assert process exits within 5 s.

Skipped on CI if `nmap` missing or not running as root (same gating as M1's smoke).

### 16.4 Frontend tests

**None automated in M2.** Manual smoke checklist (in README under "M2 manual smoke"):
1. `sudo netmap up` on a real LAN.
2. Graph populates within 60 s.
3. Side panel renders on node click.
4. "Scan now" triggers; timeline updates live.
5. Disconnect Wi-Fi for 30 s, reconnect — SSE recovers; backlog catches up.
6. DevTools: no console errors, no failed network requests.
7. `prefers-reduced-motion: reduce` — animations disabled.

### 16.5 CI

The existing `.github/workflows/ci.yml` runs `ruff check src tests` + `pytest -m "not integration"`. Adding `tests/api/` and `tests/unit/test_loop.py` etc. is automatic — they're collected by pytest.

---

## 17. Operational details

- **Logging:** stderr. `--log-format json` for structured logs, human-readable default. All log lines include `scan_id` when applicable.
- **CLI:**
  - `sudo netmap up` — defaults: `--bind 127.0.0.1 --port 8765 --interval 60`, auto-detects local CIDR.
  - `sudo netmap up --target 192.168.1.0/24 --target 10.0.0.0/24` — explicit targets override auto-detect.
  - `sudo netmap up --port 9000` — alternate port.
  - `sudo netmap up --no-open` — don't auto-open the browser (default behavior is to open if `webbrowser.open` is available and we're not in CI).
- **Signal handling:** uvicorn handles SIGINT/SIGTERM → triggers `lifespan` shutdown.
- **DB location:** `~/.netmap/state.db` (unchanged from M1).
- **Static files:** served via `StaticFiles(directory=resources.files("netmap").joinpath("ui"))`. `pyproject.toml`'s existing `force-include` is extended to include `src/netmap/ui/`.
- **Browser support:** evergreen Chrome / Firefox / Safari / Edge. SSE is native everywhere modern.
- **Resource footprint (measured target):** scanning a /24 every 60 s with one SSE client connected — CPU 2–5 % idle, RSS ≤ 100 MB.

---

## 18. Out of scope

- Passive sniffer + the gateway-traversal CIDR-discovery flow → **M3**.
- Mutation endpoints beyond `POST /scans` → **M3**.
- Non-loopback bind + bearer-token auth → **M3**.
- Layout switcher, search input, filter pills in the UI → **M3+**.
- Frontend automated tests (Playwright) → **M3+** (only if the UI grows beyond what manual smoke can cover).
- Vulnerability awareness, CVE lookup, EPSS/KEV — see `docs/ROADMAP.md` for the v2/v3 product direction.

---

## 19. Approval log

- 2026-05-25 — design brainstormed end-to-end through the superpowers `brainstorming` skill; sections 1–5 confirmed by stakeholder. Visual identity chosen: Direction B (Terminal Console) + Geist Mono. Frontend stack: vanilla JS + CDN, no build.
- _pending_ — final spec review by stakeholder before implementation-plan phase.
