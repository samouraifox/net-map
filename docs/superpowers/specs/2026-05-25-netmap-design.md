# net-map — Design Spec

**Status:** Draft (awaiting user approval)
**Date:** 2026-05-25
**Author:** Aymen
**Stakeholders:** Aymen (senior cybersecurity engineer & developer)

---

## 1. Summary

**net-map** is a single-process Python CLI tool that builds and visualizes a continuous inventory of one or more local networks. It wraps `nmap` for active scanning, performs ARP sweeps via `scapy`, runs a passive sniffer for ARP/DHCP/mDNS/LLDP/CDP, and renders the result as an interactive subnet-grouped topology graph in a local web UI.

Operator runs `sudo netmap up`; the app launches a FastAPI server on `127.0.0.1:8765`, starts a 60-second scan loop, and begins passive capture in a background thread. The UI updates over Server-Sent Events as hosts are discovered, ports change, and subnets are traversed. Pressing Ctrl-C cleanly stops everything — there is no daemon, no cron job, no installed service.

## 2. Goals

- Continuously inventory **the networks the operator declares as theirs** (configured CIDR list + optionally gateway-discovered adjacent subnets).
- Unify three discovery sources — active nmap, active ARP, and passive packet sniffing — into a single canonical host record.
- Preserve a history of network state through per-scan snapshots, with a "what changed" event timeline.
- Render the live topology as an interactive subnet-grouped graph that an operator can use to spot rogue or unexpected devices at a glance.
- Stay foreground-only and single-process for v1; design the module boundaries so the scanner can be split into a separate privileged daemon later without rewriting consumers.

## 3. Non-goals (v1)

- Background daemonization, systemd integration, scheduled cron, multi-user web auth beyond a bearer token.
- Active alerting (desktop notifications, webhooks, email).
- Importing existing nmap XML or pcap files (deferred to v2).
- Vulnerability scanning, CVE correlation, exploitability scoring.
- Cross-host federation (multiple net-map instances reporting to a central pane).
- Windows/macOS-specific scan paths (Linux-first; macOS may work via `scapy` but is not a v1 test target).
- Containerization or distribution as a service.

## 4. Use case driving the defaults

> "I want a continuous, low-friction inventory of the network(s) I own, that I can open up when I want and see the current state plus what's changed."

This shapes every default: persistent SQLite store, 60s scan cadence, snapshot-on-every-scan retention, subnet-grouped graph layout, accordion side-panel with risk-coded ports.

---

## 5. Architecture

Single Python ≥3.13 process. Five in-process subsystems with clean module boundaries so the scanner can graduate to a separate privileged daemon later.

```
┌──────────────────────────────────────────────────┐
│  CLI  (Typer)                                    │
│  netmap up · scan · subnets · diff · export …    │
└──────────────┬───────────────────────────────────┘
               │ launches
┌──────────────▼───────────────────────────────────┐
│  Process lifespan (FastAPI lifespan ctx-manager) │
│  starts →  scan_loop  (asyncio task, 60s tick)   │
│         →  passive_sniffer (background thread)   │
│         →  uvicorn web server                    │
│  stops  →  all three shut down on Ctrl-C         │
└──────────────┬───────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────┐
│  Scanner core (library)                          │
│  ├─ active.nmap    ├─ active.arp                 │
│  ├─ passive.sniff (scapy, thread)                │
│  ├─ gateway.traverse (hop-limited, allowlisted)  │
│  └─ correlation (facts → host record + events)   │
└──────────────┬───────────────────────────────────┘
               │ reads/writes
┌──────────────▼───────────────────────────────────┐
│  Storage (SQLite via sqlite3 + pydantic)         │
└──────────────────────────────────────────────────┘
```

### 5.1 Flow

1. Scheduler-free `scan_loop` ticks every `scan.interval_s` (default 60s) and runs the `discover` scan. A second, independent timer in the same loop fires every `scan.default_scan_interval_s` (default 600s) and kicks off a `default` scan as a non-blocking subprocess. `deep` is manual-only and never auto-triggered.
2. Active scanners (`arp`, `nmap discover`) run; their `AsyncIterator[Fact]` outputs are collected.
3. The passive sniffer's bounded `queue.Queue` is drained — anything it observed since the last tick is added to the fact list.
4. `correlation.correlate(facts, db, scan_id)` merges all facts into host records, upserts the DB, diffs against the previous `host_snapshot`, and returns a list of `Event`s.
5. Events are written to the `event` table and published on the in-process async event bus.
6. The web layer's SSE endpoint streams the events to all connected browsers; the frontend re-renders only the affected Cytoscape nodes/edges.

### 5.2 Threading model

| Thread / task                            | Purpose                                                                       |
|------------------------------------------|-------------------------------------------------------------------------------|
| Main thread, asyncio event loop          | FastAPI, scan loop, correlation, DB writes, event bus                         |
| Thread 1 (`passive.py`)                  | `scapy.sniff` — blocking; pushes parsed packets into a `queue.Queue`          |
| Short-lived `asyncio.to_thread` workers  | ARP `scapy.srp` calls and other blocking scapy operations                     |
| Subprocesses (`asyncio.create_subprocess_exec`) | `nmap` invocations; non-blocking from the loop's perspective         |

All threads/tasks observe a single shared `stop = asyncio.Event` (mirrored to a `threading.Event` for the sniffer thread). Ctrl-C triggers it; everything drains and exits.

---

## 6. Repo layout

```
net-map/
├── pyproject.toml            # uv-managed, Python ≥3.13
├── README.md
├── .gitignore
├── docs/superpowers/specs/   # this file + future specs
├── src/netmap/
│   ├── __init__.py
│   ├── __main__.py           # python -m netmap → cli
│   ├── cli.py                # Typer entry point
│   ├── config.py             # ~/.netmap/config.toml loader
│   ├── models.py             # Pydantic + Fact types
│   ├── storage.py            # SQLite schema + queries
│   ├── correlation.py        # facts → host record + events
│   ├── oui.py                # MAC vendor lookup (bundled IEEE CSV)
│   ├── data/oui.csv          # bundled OUI fixture
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── base.py           # ActiveScanner / PassiveScanner Protocols
│   │   ├── nmap_scanner.py
│   │   ├── arp_scanner.py
│   │   ├── passive.py        # scapy sniffer (threaded)
│   │   ├── gateway.py        # traversal, hop limit, allowlist
│   │   ├── safety.py         # pure-function target validation
│   │   └── loop.py           # scan_loop async function
│   ├── server/
│   │   ├── __init__.py
│   │   ├── app.py            # FastAPI app + lifespan
│   │   ├── routes.py         # REST + SSE
│   │   └── events.py         # async event bus
│   └── ui/                   # static files served by FastAPI
│       ├── index.html
│       ├── app.js            # cytoscape + SSE client
│       └── styles.css
└── tests/
    ├── unit/
    │   ├── test_correlation.py
    │   ├── test_storage.py
    │   ├── test_safety.py
    │   ├── test_gateway.py
    │   └── test_oui.py
    └── integration/
        ├── test_scan_smoke.py
        ├── test_passive_replay.py
        ├── fixtures/dhcp-discover.pcap
        └── fixtures/mdns-advert.pcap
    └── api/
        └── test_api.py
```

---

## 7. Data model

### 7.1 Identity rule

A host is canonically identified by its MAC address when known. For hosts seen only via nmap from across a router (no MAC available), the fallback key is `(primary_ip, subnet_id)`. If a host with an IP-fallback identity later picks up a MAC observation (because we scanned its subnet), the two records merge.

**`primary_ip` semantics:** the most recently observed IP for the host. When DHCP reassigns, `primary_ip` updates, the prior IP is recorded in `host_ip` history, and an `ip.changed` event is emitted. The `host_ip` table is the authoritative IP history.

### 7.2 SQLite schema

```sql
CREATE TABLE host (
  id          INTEGER PRIMARY KEY,
  mac         TEXT,
  primary_ip  TEXT NOT NULL,
  hostname    TEXT,
  vendor      TEXT,
  os_family   TEXT,
  os_detail   TEXT,
  device_type TEXT,                       -- router | server | endpoint | iot | unknown
  trusted     INTEGER NOT NULL DEFAULT 0,
  first_seen  TEXT NOT NULL,              -- ISO-8601
  last_seen   TEXT NOT NULL,
  notes       TEXT
);
CREATE UNIQUE INDEX uq_host_mac ON host(mac) WHERE mac IS NOT NULL;
CREATE INDEX idx_host_ip ON host(primary_ip);

CREATE TABLE host_ip (
  host_id    INTEGER REFERENCES host(id) ON DELETE CASCADE,
  ip         TEXT NOT NULL,
  subnet_id  INTEGER REFERENCES subnet(id),
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  PRIMARY KEY (host_id, ip)
);

CREATE TABLE subnet (
  id            INTEGER PRIMARY KEY,
  cidr          TEXT UNIQUE NOT NULL,
  label         TEXT,
  source        TEXT NOT NULL,            -- "config" | "discovered"
  enabled       INTEGER NOT NULL DEFAULT 1,
  hop_distance  INTEGER NOT NULL DEFAULT 0,
  first_seen    TEXT NOT NULL
);

CREATE TABLE port (
  host_id    INTEGER REFERENCES host(id) ON DELETE CASCADE,
  protocol   TEXT NOT NULL,               -- "tcp" | "udp"
  number     INTEGER NOT NULL,
  state      TEXT NOT NULL,               -- "open" | "filtered" | "closed"
  service    TEXT,
  version    TEXT,
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  PRIMARY KEY (host_id, protocol, number)
);

CREATE TABLE edge (
  id          INTEGER PRIMARY KEY,
  src_host_id INTEGER REFERENCES host(id) ON DELETE CASCADE,
  dst_host_id INTEGER REFERENCES host(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,              -- "gateway" | "arp" | "broadcast" | "observed"
  weight      INTEGER NOT NULL DEFAULT 1,
  last_seen   TEXT NOT NULL,
  UNIQUE (src_host_id, dst_host_id, kind)
);

CREATE TABLE scan (
  id         INTEGER PRIMARY KEY,
  started_at TEXT NOT NULL,
  ended_at   TEXT,
  source     TEXT NOT NULL,               -- "active.nmap" | "active.arp" | "passive"
  target     TEXT,                        -- CIDR or "passive"
  mode       TEXT,                        -- "discover" | "default" | "deep" | NULL for passive
  status     TEXT NOT NULL,               -- "running" | "ok" | "error" | "skipped"
  hosts_seen INTEGER NOT NULL DEFAULT 0,
  notes      TEXT
);

CREATE TABLE host_snapshot (
  id          INTEGER PRIMARY KEY,
  scan_id     INTEGER REFERENCES scan(id) ON DELETE CASCADE,
  host_id     INTEGER REFERENCES host(id) ON DELETE CASCADE,
  ip          TEXT NOT NULL,
  hostname    TEXT,
  os_detail   TEXT,
  device_type TEXT,
  open_ports  TEXT,                       -- JSON: [{"proto":"tcp","port":22,"svc":"ssh","ver":"OpenSSH 9.0"}]
  captured_at TEXT NOT NULL
);
CREATE INDEX idx_snap_scan ON host_snapshot(scan_id);
CREATE INDEX idx_snap_host ON host_snapshot(host_id, captured_at);

CREATE TABLE event (
  id      INTEGER PRIMARY KEY,
  ts      TEXT NOT NULL,
  scan_id INTEGER REFERENCES scan(id),
  host_id INTEGER REFERENCES host(id),
  kind    TEXT NOT NULL,                  -- host.new | host.gone | port.opened | port.closed | ip.changed | edge.new | subnet.discovered | subnet.approved
  payload TEXT                            -- JSON for UI rendering
);
CREATE INDEX idx_event_ts ON event(ts);
```

### 7.3 Pydantic mirrors & Fact types

`models.py` defines DTOs that mirror the SQL tables (`Host`, `Port`, `Edge`, `Subnet`, `Scan`, `HostSnapshot`, `Event`) for use by the API and correlation layer. Alongside them, the `Fact` family — in-memory observations a scanner emits before correlation:

```python
HostKey = NamedTuple("HostKey", [("mac", str | None), ("ip", str)])

class MacFact(BaseModel):       mac: str; ip: str; vendor: str | None = None; src: str
class PortFact(BaseModel):      host_key: HostKey; proto: Literal["tcp","udp"]; port: int; state: str; service: str | None = None; version: str | None = None
class EdgeFact(BaseModel):      src: HostKey; dst: HostKey; kind: str
class OsFact(BaseModel):        host_key: HostKey; family: str | None = None; detail: str | None = None
class HostnameFact(BaseModel):  host_key: HostKey; hostname: str; src: str
class DeviceTypeFact(BaseModel): host_key: HostKey; device_type: str  # router/endpoint/server/iot
```

### 7.4 Retention

A retention task runs once per hour, in-loop:

- `host_snapshot` rows older than `retention.snapshot_days` (default 30) → deleted.
- `scan` rows older than `retention.scan_days` (default 30) → deleted (cascades to remaining snapshots).
- `event` rows → kept indefinitely (small, useful for audit). Configurable retention available but defaults to forever.
- Current-state tables (`host`, `port`, `edge`, `subnet`, `host_ip`) are **never** auto-pruned — they reflect "what exists right now."

---

## 8. Scanner subsystem

### 8.1 Adapter Protocols

```python
class ActiveScanner(Protocol):
    name: ClassVar[str]                                   # "active.nmap" | "active.arp"
    async def scan(self, targets: list[IPv4Network],
                   mode: ScanMode) -> AsyncIterator[Fact]: ...

class PassiveScanner(Protocol):
    name: ClassVar[str]                                   # "passive.sniff"
    def start(self, on_fact: Callable[[Fact], None],
              stop: threading.Event) -> None: ...         # runs in a thread
```

### 8.2 Active · nmap (`nmap_scanner.py`)

Wraps the `nmap` binary via `asyncio.create_subprocess_exec` with `-oX -` (XML on stdout). XML is parsed incrementally into `Fact`s (`MacFact`, `PortFact`, `OsFact`, `HostnameFact`, `DeviceTypeFact`).

| Mode      | Flags                                              | Typical /24    | When it runs                          |
|-----------|----------------------------------------------------|----------------|---------------------------------------|
| `discover`| `-sn -PR -PE -PA80,443 -T4`                         | 5–15 sec       | every 60s loop iteration              |
| `default` | `-sS -O --top-ports 100 -T4 --host-timeout 5m --max-retries 2` | 2–10 min | every `default_scan_interval_s` (default 600s) |
| `deep`    | `-sS -sV -O -p- -T3 --host-timeout 30m --max-retries 2` | 30 min – several hours | manual: `netmap scan --deep` only |

**Runaway protection.** `nmap_scanner.py` maintains `Set[tuple[mode, target_cidr]]` of in-flight scans. When a tick fires and the same signature is already running, it writes a `scan` row with `status="skipped"`, logs `scan skip: <mode> on <cidr> still running since <ts>`, and continues. `--stats-every 10s` is enabled; the parser updates the running scan row's `notes` field with `"scanning N/M hosts · Xs elapsed"` so the UI can show live progress.

### 8.3 Active · ARP (`arp_scanner.py`)

Pure `scapy.srp` issued via `asyncio.to_thread`:

```python
ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
             timeout=2, verbose=False, iface=iface)
for _, rcv in ans:
    yield MacFact(mac=rcv.hwsrc, ip=rcv.psrc, src=self.name)
```

Runs on every loop tick. Catches devices that won't respond to ICMP (printers, embedded IoT, etc.). Local-subnet only (ARP is link-layer).

### 8.4 Passive sniffer (`passive.py`)

Single background thread, `scapy.sniff(filter=..., prn=callback, store=False)`. BPF filter:

```
arp
 or (udp port 67 or 68)            -- DHCP DISCOVER/REQUEST → hostname
 or (udp port 5353)                -- mDNS → bonjour names + service advertisements
 or (ether proto 0x88cc)           -- LLDP → switch/AP identity
 or (ether dst 01:00:0c:cc:cc:cc)  -- CDP
```

Each captured packet is parsed into a `Fact` and pushed into a bounded `queue.Queue(maxsize=10_000)` with drop-oldest on overflow. The scan loop drains the queue once per tick.

### 8.5 Gateway traversal (`gateway.py`)

Runs after each `default` scan completes. Algorithm:

1. **Identify gateways** — hosts whose IP appears as a default route in `ip route`, hosts with `device_type='router'` from nmap fingerprinting, or hosts that appear as the next-hop in observed traceroutes.
2. **Derive candidate subnets** — for each gateway, combine: (a) the local routing table, (b) `traceroute -n -m max_hop_distance` to a public anchor, (c) reverse DNS of the gateway's other interfaces if observable.
3. **Filter** each candidate through `safety.py` (see §11) and against `subnet.hop_distance > config.max_hop_distance`.
4. **Persist** survivors as `subnet` rows with `source='discovered'`, `enabled=0`. An `event` row `kind="subnet.discovered"` is emitted.

Discovered subnets are **not** scanned until the operator runs `netmap subnets approve <cidr>` or sets `safety.auto_approve_discovered = true` in config. The UI shows discovered subnets in a "pending approval" list with an explicit "Approve" button.

### 8.6 Correlation (`correlation.py`)

Pure function. Signature:

```python
def correlate(facts: list[Fact], db: Storage, scan_id: int) -> list[Event]:
    ...
```

Steps:

1. Group facts by `HostKey` (MAC primary, IP fallback).
2. For each group, build a `HostUpdate` by merging fields: latest non-null wins for most fields; `open_ports` is the set-union across the iteration; `vendor` derives from OUI lookup if not provided.
3. Match the `HostKey` to an existing `host` row — by MAC if present, else by `(primary_ip, subnet_id)`.
4. If a previously IP-only host now has a MAC, merge the two host rows (re-parent `host_ip`, `port`, `edge`, `host_snapshot` rows; delete the obsolete host row).
5. Upsert the host row inside a per-host transaction; update `host_ip`, `port`, `edge` as needed.
6. Diff the new state vs the most recent `host_snapshot` for this host. Emit `Event`s for: `host.new`, `host.gone`, `port.opened`, `port.closed`, `ip.changed`, `edge.new`.
7. Insert the new `host_snapshot` row.

Correlation **never** issues network calls, opens sockets, or invokes scanners. Its inputs are facts and a `Storage` interface; its outputs are DB writes and a list of events. This makes the entire correlation surface unit-testable with hand-built fact lists.

---

## 9. Web API

FastAPI on uvicorn. By default bound to `127.0.0.1:8765`. Static files (UI) served at `/`. API under `/api/v1`. CORS disabled (loopback only by default).

### 9.1 REST endpoints

| Method | Path                          | Purpose                                                      |
|--------|-------------------------------|--------------------------------------------------------------|
| GET    | `/api/v1/hosts`               | List hosts. Filters: `?subnet=<id>`, `?trusted=<bool>`, `?q=<search>`. |
| GET    | `/api/v1/hosts/{id}`          | Full host detail: ports, edges, IP history, recent events.   |
| PATCH  | `/api/v1/hosts/{id}`          | Mutate operator-editable fields: `trusted`, `notes`, `device_type` override, `hostname` override. |
| GET    | `/api/v1/edges`               | List edges. Filters: `?kind=`, `?since=`.                    |
| GET    | `/api/v1/subnets`             | List subnets w/ status (source, enabled, hop_distance, last scan). |
| POST   | `/api/v1/subnets`             | Add a CIDR to track. Body: `{cidr, label?}`.                 |
| POST   | `/api/v1/subnets/discover`    | Run one gateway-traversal pass. Body: `{hops?}` (defaults to `config.max_hop_distance`). |
| PATCH  | `/api/v1/subnets/{id}`        | `enabled`, label, approve discovered.                        |
| DELETE | `/api/v1/subnets/{id}`        | Untrack. Only `source='config'` subnets may be deleted.      |
| GET    | `/api/v1/scans`               | Recent scan rows (provenance + status, paginated).           |
| POST   | `/api/v1/scans`               | Trigger ad-hoc scan. Body: `{mode, targets?, confirm?}`. `confirm: true` is required to pass safety checks for public-IP targets (mirrors the `--i-understand` CLI flag). |
| GET    | `/api/v1/events`              | Paginated change-event timeline. Filters: `?since=`, `?host_id=`, `?kind=`. |
| GET    | `/api/v1/config`              | Current config snapshot (read-only).                         |
| PATCH  | `/api/v1/config`              | Mutate runtime-settable fields (e.g. `interval_s`, `max_hop_distance`, `auto_approve_discovered`). |
| GET    | `/api/v1/stream`              | Server-Sent Events. Emits each event as `data: <json>\n\n`.  |

### 9.2 SSE payload shape

```json
{
  "id": 1234,
  "ts": "2026-05-25T14:32:11.408Z",
  "scan_id": 87,
  "host_id": 42,
  "kind": "port.opened",
  "payload": { "proto": "tcp", "port": 9000, "service": "http", "version": "Portainer" }
}
```

### 9.3 Authentication

- Default (`bind = 127.0.0.1`): no auth; loopback only.
- If `bind != 127.0.0.1`: server refuses to start unless `server.bearer_token` is set in config. All `/api/v1/*` and `/stream` then require `Authorization: Bearer <token>`. UI bootstrap reads the token from a `?t=` URL parameter that the CLI prints on startup.

---

## 10. Frontend

Single static page, no build step. Cytoscape.js loaded from CDN; vanilla JS + CSS.

### 10.1 Topology graph

- **Library:** Cytoscape.js with `cose-bilkent` and `dagre` layout extensions.
- **Default layout:** subnet-grouped — each tracked subnet is a Cytoscape compound parent node; hosts are children, the gateway pinned at the box edge with a single inter-subnet edge to the gateway in the adjacent box.
- **Layout switcher** (top bar): subnet-grouped (default), force-directed (flat), hierarchical (tree from gateways down).
- **Node styling** by `device_type`:
  - router/gateway → red diamond
  - server → blue square
  - endpoint → gray circle
  - iot → green circle (smaller)
  - unknown → gray circle (smaller, dashed border)
- **Edge styling** by `kind`: gateway edges thicker, observed edges thinner with weight reflected in opacity.
- Click a node → opens the side panel.

### 10.2 Host-detail side panel (right side, collapsible)

**Layout:** v1 ships the **accordion** layout only. (The `ui.host_detail_layout` config key is reserved for future expansion to dense / tabbed alternatives; non-default values are accepted by the config parser but fall back to accordion in v1.) Sections, with `Overview` and `Open ports` expanded by default; `Edges`, `History`, `Notes` collapsed. Browser-local state remembers per-section expansion.

Sections:
1. **Header bar** (always visible): risk dot · IP · trusted tag · device-type tag · last-seen.
2. **Overview**: hostname, MAC, vendor, OS, first/last seen.
3. **Open ports**: scrollable list, each row gets a left-border accent + tinted background by risk:
   - **red** (high): SMB (445), RDP (3389), Telnet (23), unauthenticated DB ports (MongoDB 27017, Redis 6379, Elasticsearch 9200, MySQL 3306 if banner suggests no-auth)
   - **yellow** (elevated): SSH (22), admin web UIs (9000–9999), VNC (5900), Docker API (2375/2376)
   - **green** (normal): HTTP/S, common app ports
   - **gray** (info): mDNS, broadcast, unclassified
   - Heading shows risk roll-up: `Open ports · 8 · 1 high · 2 elev`.
4. **Edges**: list of host-to-host relationships with kind + weight + last-seen.
5. **History**: this host's recent change events (paginated, with "load older").
6. **Notes**: operator-editable freetext + "Mark trusted" toggle, "Override device type" select.

### 10.3 Subnets panel (left side, collapsible)

- List of tracked subnets grouped by source (`config` vs `discovered`).
- Each row: CIDR, label, enabled toggle, hop_distance, last scan timestamp.
- `max_hop_distance` numeric input at the top — writes to config via `PATCH /api/v1/config`; takes effect on next gateway-traversal pass without restart.
- "Discover via gateway" button → `POST /api/v1/subnets/discover`.
- Discovered subnets show an explicit `[Approve]` button until enabled.

### 10.4 Timeline strip (bottom, collapsible)

Scrollable event feed, latest first. Click an event with a host_id → graph centers and zooms to that host, side panel opens. Filters by event kind. Auto-updates from the SSE stream.

---

## 11. CLI

Built with Typer. `netmap` with no args prints help.

```
netmap up [--max-hops N] [--interval 60] [--no-passive] [--port 8765] [--bind 127.0.0.1]
    Foreground app: web UI, scan loop, passive sniffer. Ctrl-C tears down.

netmap scan --mode {discover|default|deep} [--target CIDR ...] [--i-understand]
    Standalone ad-hoc scan. Synchronous; prints results, exits.

netmap subnets {list,add,remove,approve,discover}
    Manage tracked CIDRs.
    `add <cidr> [--label TEXT]`
    `remove <cidr>`                           # config-source only
    `approve <cidr>`                          # enable a discovered subnet
    `discover [--hops N]`                     # run one gateway-traversal pass

netmap diff [--since 1h|<iso>] [--host <name-or-ip>]
    Print event timeline. Default: --since 1h.

netmap export --format {json|graphml|cytoscape} [--out PATH]
    Dump the current graph.

netmap update-oui
    Refresh the bundled IEEE OUI CSV.

netmap config {show, set <key> <value>}
    Read or mutate ~/.netmap/config.toml.

netmap db {path, migrate, vacuum, reset}
    Operational utilities. `reset` requires --yes-really-delete.
```

---

## 12. Configuration file

Path: `~/.netmap/config.toml` (created with defaults on first run). All keys settable at runtime via `PATCH /api/v1/config` unless noted.

```toml
[server]
bind = "127.0.0.1"          # restart required
port = 8765                  # restart required
bearer_token = ""            # required if bind != 127.0.0.1

[scan]
interval_s = 60                       # `discover` scan cadence — runs every N seconds
default_scan_interval_s = 600         # `default` scan cadence — independent timer, runs every N seconds
default_scan_host_timeout = "5m"
deep_scan_host_timeout = "30m"
passive = true                        # restart required

[safety]
deny_cidrs = ["0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4"]
allow_public_scan = false
max_target_hosts = 65536              # /16 = 65,536 — rejects ranges larger than this
max_hop_distance = 1
auto_approve_discovered = false

[ui]
default_layout = "subnet-grouped"     # subnet-grouped | force-directed | hierarchical
host_detail_layout = "accordion"      # accordion | dense | tabbed

[retention]
snapshot_days = 30
scan_days = 30
events_keep_forever = true

[passive]
buffer_size = 10000
filter = "arp or (udp port 67 or 68) or (udp port 5353) or (ether proto 0x88cc) or (ether dst 01:00:0c:cc:cc:cc)"
```

---

## 13. Privilege & safeguards

### 13.1 Required privileges

- Raw sockets for ARP and passive sniffing → `CAP_NET_RAW`.
- nmap SYN scan → `CAP_NET_RAW` + `CAP_NET_ADMIN`, or root.
- The CLI verifies on startup; if neither is met, prints:

  ```
  net-map needs raw-socket privileges. Either:
    sudo netmap up
  or grant once:
    sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
  ```

  and exits 1.

### 13.2 Target validation (`scanner/safety.py`)

A single pure function `validate_target(cidr, config) -> ValidationResult` enforces:

1. **Overlap with `deny_cidrs`** → reject (e.g. loopback, link-local, multicast).
2. **Public IP space** → reject unless `allow_public_scan=true` **and** the caller passed `--i-understand` on CLI or set `confirm=true` in the API body.
3. **Range too large** → reject if `cidr.num_addresses > max_target_hosts` (default 65,536, i.e. /16 max). Guards against `0.0.0.0/0`, `10.0.0.0/8`, typos.
4. **Hop-distance breach** → reject if the candidate has `hop_distance > max_hop_distance` (gateway-traversal-only path).

Every scanner entry point (`scan_loop`, `netmap scan`, `POST /api/v1/scans`) runs targets through `validate_target` before dispatch. There is no bypass path.

### 13.3 Audit trail

Every scan run writes a `scan` row with `started_at`, `ended_at`, `source`, `target`, `mode`, `status`, `hosts_seen`. Every config-mutating CLI/API call emits an `event` row. The `netmap diff` command and the UI timeline read from these.

---

## 14. Testing

### 14.1 Unit (pytest)

| File                       | Focus                                                                                  |
|----------------------------|----------------------------------------------------------------------------------------|
| `test_correlation.py`      | Largest surface. Hand-built fact lists exercising: MAC↔IP fallback, DHCP IP change, port open/close, vendor merging, host-row merge after MAC discovery. |
| `test_safety.py`           | `validate_target` across deny_cidrs, RFC1918 vs public, prefix size, hop distance, `--i-understand` gate. |
| `test_storage.py`          | Schema bootstrap, retention GC at 30 days, idempotent upserts, host-row merge transactional integrity. |
| `test_gateway.py`          | Given a fake routing table + gateway facts, assert which CIDRs land with which `hop_distance`. |
| `test_oui.py`              | Bundled OUI fixture lookup for several known MAC prefixes.                              |

### 14.2 Integration

| File                          | Focus                                                                                  |
|-------------------------------|----------------------------------------------------------------------------------------|
| `test_scan_smoke.py`          | Boot a Python HTTP server on a random localhost high port, run `netmap scan --mode default --target 127.0.0.1/32`, assert the host + port appear. Skipped if `nmap` binary absent. |
| `test_passive_replay.py`      | Replay committed pcap fixtures (`dhcp-discover.pcap`, `mdns-advert.pcap`) through `passive.py`'s parser; assert expected `MacFact` + `HostnameFact` emitted. No live network. |

### 14.3 API

| File              | Focus                                                                                      |
|-------------------|--------------------------------------------------------------------------------------------|
| `test_api.py`     | FastAPI `TestClient`: each REST endpoint returns expected shape; SSE stream emits an event after a synthetic upsert via direct DB write + bus publish. |

### 14.4 CI scope

- Unit + API: run on every commit.
- Integration: gated on `nmap` binary availability; passive replay always runs (pcap fixtures need no live network).

---

## 15. Operational details

- **OS support:** Linux first-class (kernel ≥5.10, Python ≥3.13). macOS is best-effort. Windows is not in scope.
- **Database location:** `~/.netmap/state.db` (override via `NETMAP_DB` env var).
- **Logs:** stderr only; structured JSON on `--log-format json`, human-readable otherwise.
- **Graceful shutdown:** Ctrl-C sets the shared `stop` event; the scan loop finishes its current correlation step, the sniffer thread joins (≤2s timeout), pending nmap subprocesses are sent `SIGTERM`, the DB is `VACUUM`-checked (skip if recent), uvicorn drains. Max shutdown time: ~3s.
- **Crash safety:** scan progress is written transactionally per host; an interrupted scan leaves the DB consistent (its `scan` row is updated to `status='error'` on next startup if found in `running` state).

---

## 16. Out of scope / future work

- Importing existing nmap XML or pcap files.
- Active alerting (desktop, webhook, Slack, email).
- Multi-tenant or federated deployment.
- CVE correlation / vulnerability scoring.
- Service-graph view (e.g. cluster hosts by what they serve, not where they live).
- Switching to a privileged scanner daemon + unprivileged UI (the v1 module boundaries are designed to make this a future refactor, not a rewrite).

---

## 17. Approval log

- 2026-05-25 — design brainstormed end-to-end through the superpowers `brainstorming` skill; sections 1–7 (+ scan-timing follow-up) confirmed by stakeholder.
- _pending_ — final spec review by stakeholder before implementation-plan phase.
