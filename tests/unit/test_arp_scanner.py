from ipaddress import IPv4Network

import pytest

from netmap.models import MacFact
from netmap.scanner.arp_scanner import ArpScanner
from netmap.scanner.base import ScanMode


class TestArpScanner:
    @pytest.mark.asyncio
    async def test_yields_mac_facts_from_srp_results(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeAnswer:
            def __init__(self, hwsrc: str, psrc: str) -> None:
                self.hwsrc = hwsrc
                self.psrc = psrc

        fake_answers = [
            ((None, None), FakeAnswer("aa:bb:cc:dd:ee:01", "192.168.1.5")),
            ((None, None), FakeAnswer("aa:bb:cc:dd:ee:02", "192.168.1.7")),
        ]

        def fake_srp(_pkt, **_kwargs):
            return (fake_answers, [])

        import netmap.scanner.arp_scanner as mod
        monkeypatch.setattr(mod, "srp", fake_srp)

        scanner = ArpScanner(iface="eth0")
        facts = []
        async for f in scanner.scan(IPv4Network("192.168.1.0/24"), ScanMode.DISCOVER):
            facts.append(f)

        assert all(isinstance(f, MacFact) for f in facts)
        assert {f.ip for f in facts} == {"192.168.1.5", "192.168.1.7"}
        assert all(f.src == "active.arp" for f in facts)
