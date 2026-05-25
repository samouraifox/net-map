"""GET /api/v1/subnets — read-only in M2."""
from __future__ import annotations

from datetime import UTC, datetime

from netmap.models import Subnet


def test_get_subnets_returns_all_rows(client, storage):
    storage.insert_subnet(Subnet(
        cidr="192.168.1.0/24", source="config", enabled=True,
        hop_distance=0, first_seen=datetime.now(tz=UTC),
    ))
    storage.insert_subnet(Subnet(
        cidr="10.0.0.0/24", source="discovered", enabled=False,
        hop_distance=1, first_seen=datetime.now(tz=UTC),
    ))

    r = client.get("/api/v1/subnets")
    assert r.status_code == 200
    rows = r.json()
    assert [row["cidr"] for row in rows] == ["192.168.1.0/24", "10.0.0.0/24"]


def test_subnets_mutation_endpoints_not_registered_in_m2(client):
    # M3 will add POST/PATCH/DELETE; M2 returns 405 (method not allowed).
    assert client.post("/api/v1/subnets", json={}).status_code in (404, 405)
    assert client.patch("/api/v1/subnets/1", json={}).status_code in (404, 405)
    assert client.delete("/api/v1/subnets/1").status_code in (404, 405)
