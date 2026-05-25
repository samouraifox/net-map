"""`netmap up` CLI — flag parsing and dispatch to server.app.run."""
from __future__ import annotations

from typer.testing import CliRunner

from netmap.cli import app

runner = CliRunner()


def test_up_appears_in_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "up" in result.stdout


def test_up_invokes_server_run_with_cli_args(monkeypatch, tmp_path):
    captured: dict = {}
    def fake_run(cfg, *, db_path, cli_targets):
        captured["bind"] = cfg.server.bind
        captured["port"] = cfg.server.port
        captured["db_path"] = db_path
        captured["cli_targets"] = cli_targets
    monkeypatch.setattr("netmap.server.app.run", fake_run)

    cfg_path = tmp_path / "config.toml"
    db_path = tmp_path / "state.db"
    result = runner.invoke(app, [
        "up",
        "--bind", "127.0.0.1",
        "--port", "9876",
        "--target", "192.168.1.0/24",
        "--db", str(db_path),
        "--config", str(cfg_path),
        "--no-open",
    ])
    assert result.exit_code == 0, result.stdout
    assert captured["bind"] == "127.0.0.1"
    assert captured["port"] == 9876
    assert captured["cli_targets"] == ["192.168.1.0/24"]
    assert captured["db_path"] == db_path


def test_up_defaults_cli_targets_to_none(monkeypatch, tmp_path):
    captured: dict = {}
    def fake_run(cfg, *, db_path, cli_targets):
        captured["cli_targets"] = cli_targets
    monkeypatch.setattr("netmap.server.app.run", fake_run)

    result = runner.invoke(app, [
        "up",
        "--config", str(tmp_path / "c.toml"),
        "--db", str(tmp_path / "s.db"),
        "--no-open",
    ])
    assert result.exit_code == 0
    assert captured["cli_targets"] is None
