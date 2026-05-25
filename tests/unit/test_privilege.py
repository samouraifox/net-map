"""Privilege + nmap-binary + bind checks that gate `netmap up` startup."""
from __future__ import annotations

import pytest

from netmap.config import Config, ServerCfg
from netmap.server import privilege


def _cfg(bind: str = "127.0.0.1") -> Config:
    return Config(server=ServerCfg(bind=bind))


def test_check_or_exit_passes_when_root_and_nmap_present_and_bind_loopback(monkeypatch):
    monkeypatch.setattr(privilege, "_get_euid", lambda: 0)
    monkeypatch.setattr(privilege, "_which_nmap", lambda: "/usr/bin/nmap")
    privilege.check_or_exit(_cfg())  # must not raise / exit


def test_check_or_exit_passes_with_caps_when_not_root(monkeypatch):
    monkeypatch.setattr(privilege, "_get_euid", lambda: 1000)
    monkeypatch.setattr(privilege, "_has_net_caps", lambda: True)
    monkeypatch.setattr(privilege, "_which_nmap", lambda: "/usr/bin/nmap")
    privilege.check_or_exit(_cfg())


def test_check_or_exit_fails_without_root_or_caps(monkeypatch, capsys):
    monkeypatch.setattr(privilege, "_get_euid", lambda: 1000)
    monkeypatch.setattr(privilege, "_has_net_caps", lambda: False)
    monkeypatch.setattr(privilege, "_which_nmap", lambda: "/usr/bin/nmap")
    with pytest.raises(SystemExit) as exc:
        privilege.check_or_exit(_cfg())
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "raw-socket privileges" in err
    assert "sudo netmap up" in err


def test_check_or_exit_fails_when_nmap_missing(monkeypatch, capsys):
    monkeypatch.setattr(privilege, "_get_euid", lambda: 0)
    monkeypatch.setattr(privilege, "_which_nmap", lambda: None)
    with pytest.raises(SystemExit) as exc:
        privilege.check_or_exit(_cfg())
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "nmap binary not found" in err


def test_check_or_exit_fails_with_non_loopback_bind(monkeypatch, capsys):
    monkeypatch.setattr(privilege, "_get_euid", lambda: 0)
    monkeypatch.setattr(privilege, "_which_nmap", lambda: "/usr/bin/nmap")
    with pytest.raises(SystemExit) as exc:
        privilege.check_or_exit(_cfg(bind="0.0.0.0"))
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "non-loopback bind" in err and "M3" in err


def test_has_net_caps_parses_proc_status_capeff_bits(tmp_path, monkeypatch):
    # CapEff line containing CAP_NET_RAW (bit 13 = 0x2000) + CAP_NET_ADMIN (bit 12 = 0x1000)
    proc = tmp_path / "status"
    proc.write_text("Name:\tpython\nCapEff:\t0000000000003000\n")
    monkeypatch.setattr(privilege, "_PROC_SELF_STATUS", str(proc))
    assert privilege._has_net_caps() is True

    proc.write_text("Name:\tpython\nCapEff:\t0000000000000000\n")
    assert privilege._has_net_caps() is False
