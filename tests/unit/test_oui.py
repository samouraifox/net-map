from pathlib import Path

import pytest

from netmap.oui import lookup_vendor, normalize_mac

FIXTURE = Path(__file__).parent.parent / "fixtures" / "oui-snippet.csv"


@pytest.fixture(autouse=True)
def _use_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the OUI loader at the test fixture for the duration of this module."""
    import netmap.oui as oui_mod
    monkeypatch.setattr(oui_mod, "_OUI_CSV_PATH", FIXTURE)
    oui_mod._reset_cache()


class TestNormalizeMac:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("AA:BB:CC:DD:EE:FF", "AABBCCDDEEFF"),
            ("aa-bb-cc-dd-ee-ff", "AABBCCDDEEFF"),
            ("aabb.ccdd.eeff", "AABBCCDDEEFF"),
            ("AABBCCDDEEFF", "AABBCCDDEEFF"),
        ],
    )
    def test_normalizes(self, raw: str, expected: str) -> None:
        assert normalize_mac(raw) == expected

    def test_rejects_too_short(self) -> None:
        with pytest.raises(ValueError):
            normalize_mac("AA:BB:CC")


class TestLookupVendor:
    def test_known_prefix(self) -> None:
        assert lookup_vendor("aa:bb:cc:11:22:33") == "Test Vendor Corp"

    def test_known_dotted(self) -> None:
        assert lookup_vendor("DEAD.BEEF.0000") == "Acme Industrial"

    def test_unknown_prefix(self) -> None:
        assert lookup_vendor("12:34:56:78:90:AB") is None

    def test_invalid_mac_returns_none(self) -> None:
        assert lookup_vendor("not-a-mac") is None
