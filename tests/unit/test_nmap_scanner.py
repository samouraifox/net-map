from pathlib import Path

from netmap.models import HostnameFact, MacFact, OsFact, PortFact
from netmap.scanner.nmap_scanner import parse_nmap_xml

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
