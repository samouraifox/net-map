from pathlib import Path

import pytest

from netmap.config import DEFAULT_CONFIG_PATH, Config, load_config


class TestConfigDefaults:
    def test_default_config_path_is_path(self) -> None:
        assert isinstance(DEFAULT_CONFIG_PATH, Path)

    def test_default_values(self) -> None:
        c = Config()
        assert c.scan.interval_s == 60
        assert c.scan.default_scan_interval_s == 600
        assert c.scan.passive is True
        assert c.safety.allow_public_scan is False
        assert c.safety.max_target_hosts == 65_536
        assert c.safety.max_hop_distance == 1
        assert c.server.bind == "127.0.0.1"
        assert c.server.port == 8765
        assert c.retention.snapshot_days == 30


class TestLoadConfig:
    def test_creates_default_file_when_missing(self, tmp_path: Path) -> None:
        path = tmp_path / "config.toml"
        cfg = load_config(path)
        assert path.exists()
        assert cfg.scan.interval_s == 60

    def test_returns_existing(self, tmp_path: Path) -> None:
        path = tmp_path / "config.toml"
        path.write_text(
            '[scan]\ninterval_s = 30\n'
            '[safety]\nmax_hop_distance = 3\n'
        )
        cfg = load_config(path)
        assert cfg.scan.interval_s == 30
        assert cfg.safety.max_hop_distance == 3
        # defaults preserved for unset keys
        assert cfg.scan.default_scan_interval_s == 600

    def test_unknown_keys_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "config.toml"
        path.write_text('[scan]\nbogus_key = 1\n')
        with pytest.raises(ValueError, match="bogus_key"):
            load_config(path)
