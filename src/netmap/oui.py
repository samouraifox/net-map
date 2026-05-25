"""MAC OUI vendor lookup against the bundled IEEE CSV.

Format of the CSV: two columns, ``prefix`` (6 uppercase hex digits) and ``vendor``.
The full IEEE registration is refreshed via ``netmap update-oui`` (M3).
"""
from __future__ import annotations

import csv
import re
from importlib import resources
from pathlib import Path

_OUI_CSV_PATH: Path | None = None  # set lazily; tests can monkeypatch
_CACHE: dict[str, str] | None = None
_MAC_HEX_RE = re.compile(r"[0-9A-F]")


def _default_csv_path() -> Path:
    return Path(str(resources.files("netmap").joinpath("data/oui.csv")))


def _load() -> dict[str, str]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    path = _OUI_CSV_PATH or _default_csv_path()
    table: dict[str, str] = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            prefix = row["prefix"].strip().upper()
            vendor = row["vendor"].strip()
            if len(prefix) == 6 and vendor:
                table[prefix] = vendor
    _CACHE = table
    return table


def _reset_cache() -> None:
    """Test-only: drop the in-memory OUI cache."""
    global _CACHE
    _CACHE = None


def normalize_mac(raw: str) -> str:
    """Return ``raw`` as uppercase hex with no separators.

    Accepts ``aa:bb:cc:dd:ee:ff``, ``aa-bb-cc-dd-ee-ff``, ``aabb.ccdd.eeff``,
    or already-normalized ``AABBCCDDEEFF``. Raises ValueError for anything else.
    """
    upper = raw.upper()
    digits = "".join(ch for ch in upper if _MAC_HEX_RE.match(ch))
    if len(digits) != 12:
        raise ValueError(f"not a 48-bit MAC address: {raw!r}")
    return digits


def lookup_vendor(mac: str) -> str | None:
    """Return the vendor name for the OUI of ``mac``, or ``None`` if unknown."""
    try:
        norm = normalize_mac(mac)
    except ValueError:
        return None
    prefix = norm[:6]
    return _load().get(prefix)
