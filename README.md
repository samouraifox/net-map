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
