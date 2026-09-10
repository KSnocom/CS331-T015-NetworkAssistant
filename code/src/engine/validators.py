"""Validate and normalize network-tool inputs without executing commands."""

import ipaddress
import math
import re


class ValidationError(ValueError):
    """A tool parameter is invalid."""


def validate_ip(value: str) -> str:
    """Accept a single IPv4/IPv6 address, without CIDR or zone identifiers."""
    if not isinstance(value, str) or "/" in value or "%" in value:
        raise ValidationError("Expected an IPv4 or IPv6 address")

    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValidationError("Invalid IP address") from exc


def validate_cidr(value: str) -> str:
    """Require an explicit prefix and reject networks with host bits set."""
    if not isinstance(value, str) or "/" not in value or "%" in value:
        raise ValidationError("Expected a CIDR such as 192.168.1.0/24")

    try:
        return str(ipaddress.ip_network(value, strict=True))
    except ValueError as exc:
        raise ValidationError("Invalid CIDR or host bits are set") from exc


def validate_port(value: int) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValidationError("Port must be an integer from 1 to 65535")
    return value


def validate_protocol(value: str) -> str:
    if not isinstance(value, str):
        raise ValidationError("Protocol must be tcp, udp, or icmp")

    protocol = value.lower()

    if protocol not in {"tcp", "udp", "icmp"}:
        raise ValidationError("Protocol must be tcp, udp, or icmp")
    return protocol


def validate_port_protocol(value: str) -> str:
    protocol = validate_protocol(value)

    if protocol not in {"tcp", "udp"}:
        raise ValidationError("Port rules require tcp or udp; ICMP has no ports")
    return protocol


def validate_bandwidth(value: float) -> float:
    if type(value) not in {int, float}:
        raise ValidationError("Bandwidth must be a positive finite number")

    try:
        rate = float(value)
    except (ValueError, OverflowError) as exc:
        raise ValidationError("Invalid bandwidth") from exc

    if not math.isfinite(rate) or rate <= 0:
        raise ValidationError("Bandwidth must be a positive finite number")
    return rate


def validate_interface(value: str) -> str:
    """Conservative Linux interface syntax; existence is checked separately."""
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", value) is None
    ):
        raise ValidationError(
            "Interface must be 1-15 characters using letters, digits, _, . or -"
        )
    return value


def validate_direction(value: str) -> str:
    if not isinstance(value, str):
        raise ValidationError("Direction must be INPUT, OUTPUT, or FORWARD")

    direction = value.upper()

    if direction not in {"INPUT", "OUTPUT", "FORWARD"}:
        raise ValidationError("Direction must be INPUT, OUTPUT, or FORWARD")
    return direction
