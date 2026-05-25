"""Pure-function safety validation for scan targets.

Every scanner entry point (CLI, scan loop, API) routes through ``validate_target``.
No bypass paths: bypassing this is a bug.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import AddressValueError, IPv4Network, NetmaskValueError


class SafetyError(ValueError):
    """Raised when a scan target violates the configured safety policy."""


DEFAULT_DENY_CIDRS: tuple[str, ...] = (
    "0.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)


@dataclass
class SafetyPolicy:
    deny_cidrs: tuple[str, ...] = field(default_factory=lambda: DEFAULT_DENY_CIDRS)
    allow_public_scan: bool = False
    max_target_hosts: int = 65_536
    max_hop_distance: int = 1


def _parse(cidr: str) -> IPv4Network:
    try:
        return IPv4Network(cidr, strict=False)
    except (AddressValueError, NetmaskValueError, ValueError) as exc:
        raise SafetyError(f"could not parse target as IPv4 CIDR: {cidr!r}") from exc


def validate_target(
    target: str,
    policy: SafetyPolicy,
    *,
    confirm: bool = False,
    hop_distance: int = 0,
    override_deny: bool = False,
) -> IPv4Network:
    """Validate a single scan target against ``policy``.

    Returns the parsed ``IPv4Network`` on success; raises ``SafetyError`` otherwise.

    The ``override_deny`` flag is reserved for the smoke-test path that scans
    ``127.0.0.1/32`` deliberately. Production code never sets it.
    """
    net = _parse(target)

    if not override_deny:
        for deny in policy.deny_cidrs:
            if net.overlaps(IPv4Network(deny)):
                raise SafetyError(
                    f"{net} overlaps deny_cidrs entry {deny}"
                )

    if not net.is_private:
        if not policy.allow_public_scan:
            raise SafetyError(
                f"refusing public CIDR {net}: set allow_public_scan=true in config"
            )
        if not confirm:
            raise SafetyError(
                f"refusing public CIDR {net}: requires --i-understand confirmation"
            )

    if net.num_addresses > policy.max_target_hosts:
        raise SafetyError(
            f"{net} has {net.num_addresses} addresses; exceeds max_target_hosts={policy.max_target_hosts}"
        )

    if hop_distance > policy.max_hop_distance:
        raise SafetyError(
            f"hop_distance={hop_distance} exceeds max_hop_distance={policy.max_hop_distance}"
        )

    return net
