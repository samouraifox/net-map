# net-map

Continuous inventory and topology visualizer for local networks. Wraps `nmap` and `scapy` ARP for active discovery, and ships a foreground web UI (M2) that updates live via Server-Sent Events.

## Status

- **M1 — Foundation + CLI scanner.** `netmap scan` discovers hosts via nmap and ARP, persists results in SQLite. ✅
- **M2 — Web UI + foreground scan loop.** `netmap up` runs a continuous scan loop + FastAPI server on `127.0.0.1:8765` and serves a Cytoscape topology graph that updates live over SSE. ✅
- **M3 — Passive sniffer + gateway traversal + mutation API + non-loopback auth.** Coming next.

See [`docs/superpowers/specs/2026-05-25-netmap-design.md`](docs/superpowers/specs/2026-05-25-netmap-design.md) for the v1 design, [`docs/superpowers/specs/2026-05-25-netmap-m2-design.md`](docs/superpowers/specs/2026-05-25-netmap-m2-design.md) for M2's spec, and [`docs/ROADMAP.md`](docs/ROADMAP.md) for the v2+ direction (vuln scanning, exploit scoring).

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

### M2 — Live web UI (recommended)

Start the foreground web server + scan loop:

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

Override port:

```bash
sudo uv run netmap up --port 9000
```

Don't auto-open the browser:

```bash
sudo uv run netmap up --no-open
```

### M1 — One-shot CLI scans

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

## Develop

```bash
uv run pytest                 # unit + API tests (~5s)
uv run pytest -m integration  # smoke tests (need nmap + root)
uv run ruff check src tests
```

## License

MIT.
