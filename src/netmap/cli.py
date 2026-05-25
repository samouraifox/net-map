"""net-map CLI entry point."""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from ipaddress import IPv4Network
from pathlib import Path
from typing import Annotated

import typer

from netmap import __version__
from netmap.config import DEFAULT_CONFIG_PATH, load_config
from netmap.correlation import correlate
from netmap.models import Fact, Scan
from netmap.scanner.arp_scanner import ArpScanner
from netmap.scanner.base import ActiveScanner, ScanMode
from netmap.scanner.nmap_scanner import NmapScanner
from netmap.scanner.safety import SafetyError, SafetyPolicy, validate_target
from netmap.storage import Storage

app = typer.Typer(
    help="net-map — continuous inventory + topology visualizer",
    no_args_is_help=True,
)

DEFAULT_DB_PATH = Path("~/.netmap/state.db").expanduser()


def _make_nmap_scanner(cfg) -> NmapScanner:
    return NmapScanner(
        default_host_timeout=cfg.scan.default_scan_host_timeout,
        deep_host_timeout=cfg.scan.deep_scan_host_timeout,
    )


def _make_arp_scanner(iface: str | None) -> ArpScanner:
    return ArpScanner(iface=iface)


@app.command()
def version() -> None:
    """Print the installed netmap version."""
    typer.echo(__version__)


@app.command()
def scan(
    target: Annotated[
        list[str], typer.Option("--target", "-t", help="CIDR(s) to scan")
    ],
    mode: Annotated[
        ScanMode, typer.Option("--mode", "-m")
    ] = ScanMode.DISCOVER,
    iface: Annotated[
        str | None, typer.Option("--iface", help="Interface for ARP")
    ] = None,
    db_path: Annotated[Path, typer.Option("--db")] = DEFAULT_DB_PATH,
    config_path: Annotated[Path, typer.Option("--config")] = DEFAULT_CONFIG_PATH,
    i_understand: Annotated[
        bool,
        typer.Option(
            "--i-understand", help="Confirm public-IP scan"
        ),
    ] = False,
    allow_loopback: Annotated[
        bool,
        typer.Option(
            "--allow-loopback",
            hidden=True,
            help="Smoke-test escape hatch — overrides deny_cidrs for the supplied targets.",
        ),
    ] = False,
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
            nets.append(
                validate_target(
                    t, policy, confirm=i_understand, override_deny=allow_loopback,
                )
            )
        except SafetyError as exc:
            typer.echo(f"refused: {exc}", err=True)
            raise typer.Exit(code=2) from exc

    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = Storage(str(db_path))
    nmap = _make_nmap_scanner(cfg)
    arp = _make_arp_scanner(iface)

    asyncio.run(_run_scan(db, [nmap, arp], nets, mode))


async def _run_scan(
    db: Storage,
    scanners: list[ActiveScanner],
    targets: list[IPv4Network],
    mode: ScanMode,
) -> None:
    now = datetime.now(tz=UTC)
    target_str = ",".join(str(t) for t in targets)
    scan_id = db.start_scan(
        Scan(
            started_at=now, source="cli.scan", target=target_str,
            mode=mode.value, status="running",
        )
    )
    facts: list[Fact] = []
    try:
        for target in targets:
            for scanner in scanners:
                async for f in scanner.scan(target, mode):
                    facts.append(f)
    except Exception as exc:
        db.finish_scan(
            scan_id, ended_at=datetime.now(tz=UTC),
            status="error", hosts_seen=0,
        )
        typer.echo(f"scan error: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    # Only pass observed_subnets when the scan mode actually probes ports.
    observed = (
        [str(t) for t in targets]
        if mode in (ScanMode.DEFAULT, ScanMode.DEEP)
        else []
    )
    events = correlate(facts, db, scan_id, now=now, observed_subnets=observed)

    hosts = db._conn.execute("SELECT COUNT(*) FROM host").fetchone()[0]
    db.finish_scan(
        scan_id, ended_at=datetime.now(tz=UTC),
        status="ok", hosts_seen=int(hosts),
    )
    typer.echo(
        f"scan {scan_id}: {len(facts)} facts → {len(events)} events; "
        f"{hosts} hosts total"
    )


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


db_app = typer.Typer(help="Database utilities")
config_app = typer.Typer(help="Configuration")
app.add_typer(db_app, name="db")
app.add_typer(config_app, name="config")


@db_app.command("path")
def db_path_cmd(
    db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB_PATH,
) -> None:
    """Print the resolved database path."""
    typer.echo(str(db))


@db_app.command("vacuum")
def db_vacuum_cmd(
    db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB_PATH,
) -> None:
    """Run SQLite VACUUM."""
    s = Storage(str(db))
    s._conn.execute("VACUUM")
    s.close()


@db_app.command("reset")
def db_reset_cmd(
    db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB_PATH,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes-really-delete",
            help="Confirm permanent deletion of the database file.",
        ),
    ] = False,
) -> None:
    """Delete the database file. Requires --yes-really-delete."""
    if not yes:
        typer.echo(
            "refusing to delete; pass --yes-really-delete to confirm",
            err=True,
        )
        raise typer.Exit(code=2)
    if db.exists():
        db.unlink()


@db_app.command("migrate")
def db_migrate_cmd(
    db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB_PATH,
) -> None:
    """Run idempotent schema bootstrap (no-op if already current)."""
    Storage(str(db)).close()


@config_app.command("show")
def config_show_cmd(
    config: Annotated[Path, typer.Option("--config")] = DEFAULT_CONFIG_PATH,
) -> None:
    """Print the resolved configuration as JSON."""
    cfg = load_config(config)
    typer.echo(json.dumps(cfg.model_dump(), indent=2, default=str))
