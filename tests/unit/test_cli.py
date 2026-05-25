from pathlib import Path

import pytest
from typer.testing import CliRunner

from netmap.cli import app

runner = CliRunner()


class TestVersion:
    def test_version_prints(self) -> None:
        r = runner.invoke(app, ["version"])
        assert r.exit_code == 0
        assert "0.1.0" in r.stdout


class TestScanCommand:
    def test_scan_rejects_invalid_target(self, tmp_path: Path) -> None:
        r = runner.invoke(
            app,
            [
                "scan",
                "--target", "not-a-cidr",
                "--mode", "discover",
                "--db", str(tmp_path / "test.db"),
                "--config", str(tmp_path / "config.toml"),
            ],
        )
        assert r.exit_code != 0
        combined = (r.stdout + (r.stderr or "")).lower()
        assert "parse" in combined or "refused" in combined

    def test_scan_rejects_loopback_without_override(self, tmp_path: Path) -> None:
        r = runner.invoke(
            app,
            [
                "scan",
                "--target", "127.0.0.0/8",
                "--mode", "discover",
                "--db", str(tmp_path / "test.db"),
                "--config", str(tmp_path / "config.toml"),
            ],
        )
        assert r.exit_code != 0

    def test_scan_uses_injected_scanners(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Inject fake scanners and confirm the command ingests facts and writes hosts."""
        from ipaddress import IPv4Network

        from netmap.models import MacFact
        from netmap.scanner.base import ScanMode

        async def fake_nmap_scan(target: IPv4Network, mode: ScanMode):
            return
            yield  # pragma: no cover — makes this an async generator

        async def fake_arp_scan(target: IPv4Network, mode: ScanMode):
            yield MacFact(
                mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp"
            )

        class FakeNmap:
            name = "active.nmap"
            scan = staticmethod(fake_nmap_scan)

        class FakeArp:
            name = "active.arp"
            scan = staticmethod(fake_arp_scan)

        from netmap import cli as cli_mod
        monkeypatch.setattr(cli_mod, "_make_nmap_scanner", lambda: FakeNmap())
        monkeypatch.setattr(cli_mod, "_make_arp_scanner", lambda iface: FakeArp())

        db_path = tmp_path / "test.db"
        cfg_path = tmp_path / "config.toml"
        r = runner.invoke(
            app,
            [
                "scan",
                "--target", "192.168.1.0/24",
                "--mode", "discover",
                "--db", str(db_path),
                "--config", str(cfg_path),
            ],
        )
        assert r.exit_code == 0, r.stdout + (r.stderr or "")

        from netmap.storage import Storage
        s = Storage(str(db_path))
        rows = s._conn.execute("SELECT primary_ip FROM host").fetchall()
        assert rows == [("192.168.1.5",)]


class TestDbCommands:
    def test_db_path(self, tmp_path: Path) -> None:
        db = tmp_path / "x.db"
        r = runner.invoke(app, ["db", "path", "--db", str(db)])
        assert r.exit_code == 0
        assert str(db) in r.stdout

    def test_db_vacuum(self, tmp_path: Path) -> None:
        from netmap.storage import Storage
        db = tmp_path / "x.db"
        Storage(str(db)).close()
        r = runner.invoke(app, ["db", "vacuum", "--db", str(db)])
        assert r.exit_code == 0

    def test_db_reset_requires_flag(self, tmp_path: Path) -> None:
        from netmap.storage import Storage
        db = tmp_path / "x.db"
        Storage(str(db)).close()
        r = runner.invoke(app, ["db", "reset", "--db", str(db)])
        assert r.exit_code != 0

    def test_db_reset_with_flag(self, tmp_path: Path) -> None:
        from netmap.storage import Storage
        db = tmp_path / "x.db"
        Storage(str(db)).close()
        r = runner.invoke(
            app, ["db", "reset", "--db", str(db), "--yes-really-delete"]
        )
        assert r.exit_code == 0
        assert not db.exists()


class TestConfigCommands:
    def test_config_show(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.toml"
        r = runner.invoke(app, ["config", "show", "--config", str(cfg)])
        assert r.exit_code == 0
        assert "interval_s" in r.stdout
