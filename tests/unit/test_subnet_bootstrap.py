"""Subnet auto-detect — parse `ip route` text and infer the host's primary CIDR."""
from __future__ import annotations

from netmap.server.subnet_bootstrap import parse_iface_cidr, parse_ip_route

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
