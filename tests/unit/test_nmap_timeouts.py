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
