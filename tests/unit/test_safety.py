from ipaddress import IPv4Network

import pytest

from netmap.scanner.safety import (
    DEFAULT_DENY_CIDRS,
    SafetyError,
    SafetyPolicy,
    validate_target,
)


@pytest.fixture
def policy() -> SafetyPolicy:
    return SafetyPolicy(
        deny_cidrs=DEFAULT_DENY_CIDRS,
        allow_public_scan=False,
        max_target_hosts=65_536,
        max_hop_distance=1,
    )


class TestValidateTarget:
    def test_rfc1918_24_ok(self, policy: SafetyPolicy) -> None:
        assert validate_target("192.168.1.0/24", policy) == IPv4Network("192.168.1.0/24")

    def test_loopback_rejected(self, policy: SafetyPolicy) -> None:
        with pytest.raises(SafetyError, match="deny_cidrs"):
            validate_target("127.0.0.0/8", policy)

    def test_link_local_rejected(self, policy: SafetyPolicy) -> None:
        with pytest.raises(SafetyError, match="deny_cidrs"):
            validate_target("169.254.0.0/16", policy)

    def test_multicast_rejected(self, policy: SafetyPolicy) -> None:
        with pytest.raises(SafetyError, match="deny_cidrs"):
            validate_target("224.0.0.0/4", policy)

    def test_public_rejected_without_confirm(self, policy: SafetyPolicy) -> None:
        with pytest.raises(SafetyError, match="public"):
            validate_target("8.8.8.0/24", policy)

    def test_public_allowed_with_confirm_and_setting(self, policy: SafetyPolicy) -> None:
        policy.allow_public_scan = True
        assert validate_target("8.8.8.0/24", policy, confirm=True) == IPv4Network("8.8.8.0/24")

    def test_public_rejected_with_confirm_but_setting_off(self, policy: SafetyPolicy) -> None:
        with pytest.raises(SafetyError, match="allow_public_scan"):
            validate_target("8.8.8.0/24", policy, confirm=True)

    def test_too_large_rejected(self, policy: SafetyPolicy) -> None:
        # /15 is 131,072 addresses; default cap is 65,536
        with pytest.raises(SafetyError, match="max_target_hosts"):
            validate_target("10.0.0.0/15", policy)

    def test_at_cap_allowed(self, policy: SafetyPolicy) -> None:
        # /16 == 65,536 addresses == exact cap
        assert validate_target("10.0.0.0/16", policy) == IPv4Network("10.0.0.0/16")

    def test_single_host(self, policy: SafetyPolicy) -> None:
        result = validate_target("127.0.0.1/32", policy, override_deny=True)
        assert result == IPv4Network("127.0.0.1/32")

    def test_malformed_cidr_raises(self, policy: SafetyPolicy) -> None:
        with pytest.raises(SafetyError, match="parse"):
            validate_target("not-a-cidr", policy)

    def test_hop_distance_too_far(self, policy: SafetyPolicy) -> None:
        with pytest.raises(SafetyError, match="max_hop_distance"):
            validate_target("192.168.5.0/24", policy, hop_distance=3)

    def test_hop_distance_ok(self, policy: SafetyPolicy) -> None:
        assert validate_target("192.168.5.0/24", policy, hop_distance=1)
