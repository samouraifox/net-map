"""REST endpoints for net-map M2.

All routes hang off `/api/v1`. Static UI mounting + GET / live here too.
Handlers pull dependencies (Config, Storage, AsyncBus, in_flight) off
`request.app.state`, so the same router works against the production app
and the test app without DI plumbing.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request

from netmap.models import Event, Scan, Subnet
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


def register(app: FastAPI) -> None:
    app.include_router(api)
