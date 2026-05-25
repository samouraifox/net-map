"""REST endpoints for net-map M2.

All routes hang off `/api/v1`. Static UI mounting + GET / live here too.
Handlers pull dependencies (Config, Storage, AsyncBus, in_flight) off
`request.app.state`, so the same router works against the production app
and the test app without DI plumbing.
"""
from __future__ import annotations

import asyncio as _asyncio
import json as _json
from datetime import datetime
from ipaddress import IPv4Network

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request
from sse_starlette.sse import EventSourceResponse

from netmap.models import Event, Scan, Subnet
from netmap.scanner.loop import maybe_run
from netmap.scanner.safety import SafetyError, SafetyPolicy, validate_target
from netmap.server.schemas import (
    HostDetail,
    HostIp,
    HostSummary,
    ScanRequest,
    ScanResponse,
)

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
    since_dt = datetime.fromisoformat(since) if since else None
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
    since_dt = datetime.fromisoformat(since) if since else None
    events = db.list_events(since=since_dt, host_id=host_id, limit=limit)
    if kind:
        events = [e for e in events if e.kind == kind]
    return events


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
                except TimeoutError:
                    yield {"comment": "ping"}
                    continue
                yield {"data": _json.dumps(event.model_dump(mode="json"))}
        finally:
            bus.unsubscribe(queue)

    return EventSourceResponse(event_iter(), ping=30)


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
