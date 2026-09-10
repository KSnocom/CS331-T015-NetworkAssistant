"""Fixed network-command templates. Never accept shell command strings."""

import ipaddress
from dataclasses import dataclass

from src.engine.validators import (
    validate_ip,
    validate_port,
    validate_port_protocol,
    validate_direction,
)


@dataclass(frozen=True)
class Command:
    argv: tuple[str, ...]
    timeout_seconds: int = 10


def _iptables(family: int) -> str:
    if type(family) is not int or family not in {4, 6}:
        raise ValueError("IP family must be 4 or 6")
    return "/usr/sbin/iptables" if family == 4 else "/usr/sbin/ip6tables"


def show_firewall_rules(family: int = 4) -> Command:
    return Command((
        _iptables(family),
        "-w", "5",
        "-L", "-n", "-v", "--line-numbers",
    ))


def list_firewall_rules(family: int = 4) -> Command:
    """Machine-readable rule specifications, used for counting owned rules."""
    return Command((_iptables(family), "-w", "5", "-S"))


def _operation(operation: str, direction: str) -> tuple[str, ...]:
    direction = validate_direction(direction)

    if operation == "add":
        return ("-I", direction, "1")
    if operation == "check":
        return ("-C", direction)
    if operation == "delete":
        return ("-D", direction)

    raise ValueError("Operation must be add, check, or delete")


def firewall_ip_rule(
    operation: str,
    ip_address: str,
    direction: str = "INPUT",
) -> Command:
    ip = validate_ip(ip_address)
    direction = validate_direction(direction)
    family = ipaddress.ip_address(ip).version

    # INPUT and FORWARD match the source. OUTPUT matches the destination.
    address_flag = "-d" if direction == "OUTPUT" else "-s"

    return Command((
        _iptables(family), "-w", "5",
        *_operation(operation, direction),
        address_flag, ip,
        "-m", "comment", "--comment", "ina-v1-ip",
        "-j", "DROP",
    ))


def firewall_port_rule(
    operation: str,
    port: int,
    protocol: str,
    direction: str = "INPUT",
    family: int = 4,
) -> Command:
    port = validate_port(port)
    protocol = validate_port_protocol(protocol)

    return Command((
        _iptables(family), "-w", "5",
        *_operation(operation, direction),
        "-p", protocol, "--dport", str(port),
        "-m", "comment", "--comment", "ina-v1-port",
        "-j", "DROP",
    ))
