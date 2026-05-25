from ipaddress import IPv4Network
from pathlib import Path

import pytest

from netmap.models import HostnameFact, MacFact, OsFact, PortFact
from netmap.scanner.base import ScanMode
from netmap.scanner.nmap_scanner import NmapScanner, _flags_for_mode, parse_nmap_xml

FIX = Path(__file__).parent.parent / "fixtures"


class TestParseNmapXml:
    def test_empty(self) -> None:
        assert list(parse_nmap_xml((FIX / "nmap-empty.xml").read_text())) == []

    def test_discover_emits_mac_facts(self) -> None:
        facts = list(parse_nmap_xml((FIX / "nmap-discover-sample.xml").read_text()))
        macs = [f for f in facts if isinstance(f, MacFact)]
        assert {(m.mac.upper(), m.ip) for m in macs} == {
            ("3C:5A:B4:9D:11:E0", "192.168.1.5"),
            ("A4:5E:60:8B:C1:D2", "192.168.1.42"),
        }

    def test_discover_emits_hostnames(self) -> None:
        facts = list(parse_nmap_xml((FIX / "nmap-discover-sample.xml").read_text()))
        hostnames = [f for f in facts if isinstance(f, HostnameFact)]
        assert any(h.hostname == "nas.lan" for h in hostnames)

    def test_default_emits_open_ports(self) -> None:
        facts = list(parse_nmap_xml((FIX / "nmap-default-sample.xml").read_text()))
        ports = [f for f in facts if isinstance(f, PortFact) and f.state == "open"]
        assert {(p.proto, p.port, p.service) for p in ports} == {
            ("tcp", 22, "ssh"),
            ("tcp", 445, "microsoft-ds"),
        }

    def test_default_skips_closed_ports(self) -> None:
        facts = list(parse_nmap_xml((FIX / "nmap-default-sample.xml").read_text()))
        ports = [f for f in facts if isinstance(f, PortFact)]
        assert all(p.state == "open" for p in ports)

    def test_default_emits_os(self) -> None:
        facts = list(parse_nmap_xml((FIX / "nmap-default-sample.xml").read_text()))
        os_facts = [f for f in facts if isinstance(f, OsFact)]
        assert any(f.family == "Linux" for f in os_facts)


class TestFlagsForMode:
    def test_discover_flags(self) -> None:
        assert _flags_for_mode(ScanMode.DISCOVER) == [
            "-sn", "-PR", "-PE", "-PA80,443", "-T4",
        ]

    def test_default_flags_include_timeout(self) -> None:
        flags = _flags_for_mode(ScanMode.DEFAULT)
        assert "--host-timeout" in flags
        assert "--top-ports" in flags

    def test_deep_flags_full_port_range(self) -> None:
        flags = _flags_for_mode(ScanMode.DEEP)
        assert "-p-" in flags


class TestNmapScannerSubprocess:
    @pytest.mark.asyncio
    async def test_subprocess_failure_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeProc:
            returncode = 1

            async def communicate(self) -> tuple[bytes, bytes]:
                return (b"", b"nmap: bad flags")

        async def fake_exec(*args, **kwargs) -> FakeProc:
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
        scanner = NmapScanner()
        with pytest.raises(RuntimeError, match="bad flags"):
            async for _ in scanner.scan(
                IPv4Network("127.0.0.1/32"), ScanMode.DISCOVER
            ):
                pass

    @pytest.mark.asyncio
    async def test_subprocess_success_yields_parsed_facts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        xml = (FIX / "nmap-discover-sample.xml").read_bytes()

        class FakeProc:
            returncode = 0

            async def communicate(self) -> tuple[bytes, bytes]:
                return (xml, b"")

        async def fake_exec(*args, **kwargs) -> FakeProc:
            return FakeProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
        scanner = NmapScanner()
        facts = []
        async for f in scanner.scan(
            IPv4Network("192.168.1.0/24"), ScanMode.DISCOVER
        ):
            facts.append(f)
        assert len(facts) >= 2  # at least the two MAC facts from the fixture
