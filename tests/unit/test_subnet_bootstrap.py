"""Subnet auto-detect — parse `ip route` text and infer the host's primary CIDR."""
from __future__ import annotations

from datetime import UTC, datetime

from netmap.models import Subnet
from netmap.server import subnet_bootstrap
from netmap.server.subnet_bootstrap import parse_iface_cidr, parse_ip_route
from netmap.storage import Storage

ROUTE_LINUX = """\
default via 192.168.1.1 dev wlan0 proto dhcp metric 600
192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.42 metric 600
"""

_WLAN0_LINE = (
    "2: wlan0    inet 192.168.1.42/24 brd 192.168.1.255 scope global"
    " dynamic noprefixroute wlan0\\       valid_lft 3500sec preferred_lft 3500sec"
)
_DOCKER0_LINE = (
    "3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global"
    " docker0\\       valid_lft forever preferred_lft forever"
)
ADDR_LINUX = (
    "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"
    + _WLAN0_LINE
    + "\n"
    + _DOCKER0_LINE
    + "\n"
)


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


# ---------------------------------------------------------------------------
# run() integration tests
# ---------------------------------------------------------------------------


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
