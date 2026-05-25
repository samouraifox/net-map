import pytest
from pydantic import ValidationError

from netmap.models import (
    DeviceTypeFact,
    EdgeFact,
    HostKey,
    HostnameFact,
    MacFact,
    OsFact,
    PortFact,
)


class TestHostKey:
    def test_with_mac_and_ip(self) -> None:
        key = HostKey(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.1")
        assert key.mac == "aa:bb:cc:dd:ee:ff"
        assert key.ip == "192.168.1.1"

    def test_with_ip_only(self) -> None:
        key = HostKey(mac=None, ip="10.0.0.5")
        assert key.mac is None

    def test_is_hashable(self) -> None:
        key1 = HostKey(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.1")
        key2 = HostKey(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.1")
        assert {key1, key2} == {key1}


class TestFacts:
    def test_mac_fact(self) -> None:
        f = MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp")
        assert f.vendor is None
        assert f.src == "active.arp"

    def test_port_fact_requires_valid_proto(self) -> None:
        with pytest.raises(ValidationError):
            PortFact(
                host_key=HostKey(mac=None, ip="1.1.1.1"),
                proto="icmp",  # type: ignore[arg-type]
                port=22,
                state="open",
            )

    def test_port_fact_valid(self) -> None:
        f = PortFact(
            host_key=HostKey(mac=None, ip="1.1.1.1"),
            proto="tcp",
            port=22,
            state="open",
            service="ssh",
            version="OpenSSH 9.3",
        )
        assert f.service == "ssh"

    def test_edge_fact(self) -> None:
        f = EdgeFact(
            src=HostKey(mac="aa:bb:cc:dd:ee:01", ip="10.0.0.1"),
            dst=HostKey(mac="aa:bb:cc:dd:ee:02", ip="10.0.0.2"),
            kind="arp",
        )
        assert f.kind == "arp"

    def test_os_fact(self) -> None:
        f = OsFact(host_key=HostKey(mac=None, ip="1.1.1.1"), family="Linux", detail="Linux 5.x")
        assert f.family == "Linux"

    def test_hostname_fact(self) -> None:
        f = HostnameFact(
            host_key=HostKey(mac=None, ip="1.1.1.1"),
            hostname="nas.lan",
            src="active.nmap",
        )
        assert f.hostname == "nas.lan"

    def test_device_type_fact(self) -> None:
        f = DeviceTypeFact(host_key=HostKey(mac=None, ip="1.1.1.1"), device_type="router")
        assert f.device_type == "router"

    def test_port_fact_rejects_port_zero(self) -> None:
        with pytest.raises(ValidationError):
            PortFact(host_key=HostKey(mac=None, ip="1.1.1.1"),
                     proto="tcp", port=0, state="open")

    def test_port_fact_rejects_port_above_65535(self) -> None:
        with pytest.raises(ValidationError):
            PortFact(host_key=HostKey(mac=None, ip="1.1.1.1"),
                     proto="tcp", port=65536, state="open")

    def test_edge_fact_rejects_unknown_kind(self) -> None:
        with pytest.raises(ValidationError):
            EdgeFact(
                src=HostKey(mac=None, ip="1.1.1.1"),
                dst=HostKey(mac=None, ip="1.1.1.2"),
                kind="nonsense",  # type: ignore[arg-type]
            )

    def test_device_type_fact_rejects_unknown_type(self) -> None:
        with pytest.raises(ValidationError):
            DeviceTypeFact(host_key=HostKey(mac=None, ip="1.1.1.1"),
                            device_type="toaster")  # type: ignore[arg-type]


class TestFactConfig:
    def test_frozen(self) -> None:
        f = MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", src="active.arp")
        with pytest.raises(ValidationError):
            f.src = "different"  # type: ignore[misc]

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            MacFact(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5",
                    src="active.arp", surprise="not-allowed")  # type: ignore[call-arg]
