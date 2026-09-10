"""Validated tc command templates. No command execution."""

import ipaddress

from src.engine.command_builder import Command
from src.engine.validators import (
    validate_bandwidth,
    validate_interface,
    validate_ip,
)


TC = "/usr/sbin/tc"


def _class_id(value):
    # Assigned internally by the service, never chosen by the LLM.
    if type(value) is not int or not 1 <= value <= 65534:
        raise ValueError("Class ID must be an integer from 1 to 65534")
    return value


def _protocol(family):
    if type(family) is not int or family not in {4, 6}:
        raise ValueError("IP family must be 4 or 6")
    return "ip" if family == 4 else "ipv6"


def show_qdiscs(interface):
    interface = validate_interface(interface)
    return Command((TC, "-j", "qdisc", "show", "dev", interface))


def show_classes(interface):
    interface = validate_interface(interface)
    return Command((TC, "-j", "-s", "class", "show", "dev", interface))


def show_filters(interface):
    interface = validate_interface(interface)
    return Command((
        TC, "-j", "filter", "show",
        "dev", interface, "parent", "1:",
    ))


def add_root(interface):
    """Service must check existing qdisc ownership before calling this."""
    interface = validate_interface(interface)
    return Command((
        TC, "qdisc", "add", "dev", interface,
        "root", "handle", "1:", "htb", "default", "0",
    ))


def set_class(interface, class_id, rate_mbps):
    interface = validate_interface(interface)
    class_id = _class_id(class_id)
    rate = validate_bandwidth(rate_mbps)
    rate_argument = f"{rate:.12g}mbit"

    return Command((
        TC, "class", "replace", "dev", interface,
        "parent", "1:", "classid", f"1:{class_id:x}",
        "htb", "rate", rate_argument, "ceil", rate_argument,
    ))


def delete_class(interface, class_id):
    interface = validate_interface(interface)
    class_id = _class_id(class_id)

    return Command((
        TC, "class", "del", "dev", interface,
        "parent", "1:", "classid", f"1:{class_id:x}",
    ))


def set_filter(interface, class_id, ip_address):
    interface = validate_interface(interface)
    class_id = _class_id(class_id)
    ip = validate_ip(ip_address)
    address = ipaddress.ip_address(ip)
    destination = f"{ip}/{address.max_prefixlen}"

    return Command((
        TC, "filter", "replace", "dev", interface,
        "parent", "1:",
        "protocol", _protocol(address.version),
        "pref", str(class_id),
        "handle", str(class_id),
        "flower", "dst_ip", destination,
        "classid", f"1:{class_id:x}",
    ))


def delete_filter(interface, class_id, family=4):
    interface = validate_interface(interface)
    class_id = _class_id(class_id)

    return Command((
        TC, "filter", "del", "dev", interface,
        "parent", "1:",
        "protocol", _protocol(family),
        "pref", str(class_id),
        "handle", str(class_id),
        "flower",
    ))
