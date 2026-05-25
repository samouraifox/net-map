"""Startup checks for `netmap up`. Runs before the server binds.

Three gates: (1) root or CAP_NET_RAW+CAP_NET_ADMIN, (2) nmap on PATH,
(3) bind == 127.0.0.1 (M2 only; auth lands in M3).
"""
from __future__ import annotations

import os
import shutil
import sys

from netmap.config import Config

_PROC_SELF_STATUS = "/proc/self/status"
_CAP_NET_ADMIN = 1 << 12
_CAP_NET_RAW = 1 << 13


_NOT_PRIVILEGED = """\
net-map needs raw-socket privileges. Either:
  sudo netmap up
or grant once:
  sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
"""

_NO_NMAP = """\
nmap binary not found on PATH. Install it:
  Debian/Ubuntu:  sudo apt install nmap
  Arch:           sudo pacman -S nmap
  macOS:          brew install nmap
"""

_NON_LOOPBACK = """\
non-loopback bind requires bearer-token auth, which lands in M3.
Set [server].bind = "127.0.0.1" or wait for M3.
"""


def _get_euid() -> int:
    return os.geteuid()


def _which_nmap() -> str | None:
    return shutil.which("nmap")


def _has_net_caps() -> bool:
    try:
        with open(_PROC_SELF_STATUS) as f:
            for line in f:
                if line.startswith("CapEff:"):
                    bits = int(line.split()[1], 16)
                    return bool(bits & _CAP_NET_RAW) and bool(bits & _CAP_NET_ADMIN)
    except OSError:
        return False
    return False


def check_or_exit(cfg: Config) -> None:
    """Run all startup checks; exit 1 with stderr instruction on any failure."""
    if _get_euid() != 0 and not _has_net_caps():
        print(_NOT_PRIVILEGED, file=sys.stderr, end="")
        sys.exit(1)

    if _which_nmap() is None:
        print(_NO_NMAP, file=sys.stderr, end="")
        sys.exit(1)

    if cfg.server.bind != "127.0.0.1":
        print(_NON_LOOPBACK, file=sys.stderr, end="")
        sys.exit(1)
