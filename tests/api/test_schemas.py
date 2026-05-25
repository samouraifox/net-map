"""Schema roundtrips — model_validate + model_dump for response DTOs."""
from __future__ import annotations

from datetime import UTC, datetime

from netmap.scanner.base import ScanMode
from netmap.server.schemas import (
    HostIp,
    HostSummary,
    ScanRequest,
    ScanResponse,
)


def test_host_summary_roundtrip():
    payload = {
        "id": 1, "mac": "aa:bb:cc:dd:ee:01", "primary_ip": "192.168.1.10",
        "hostname": "printer", "vendor": "Brother", "device_type": "printer",
        "trusted": False, "open_port_count": 2,
        "last_seen": datetime.now(tz=UTC),
    }
    hs = HostSummary(**payload)
    assert hs.model_dump()["primary_ip"] == "192.168.1.10"


def test_host_ip_requires_ip_and_timestamps():
    ip = HostIp(ip="192.168.1.10",
                first_seen=datetime.now(tz=UTC),
                last_seen=datetime.now(tz=UTC))
    assert ip.ip == "192.168.1.10"


def test_scan_request_defaults():
    req = ScanRequest(mode=ScanMode.DISCOVER)
    assert req.targets is None
    assert req.confirm is False


def test_scan_response_shape():
    resp = ScanResponse(scan_id=42, accepted_targets=["192.168.1.0/24"])
    assert resp.model_dump() == {"scan_id": 42, "accepted_targets": ["192.168.1.0/24"]}
