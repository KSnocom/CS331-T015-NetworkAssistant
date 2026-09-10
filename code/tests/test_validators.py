import pytest

from src.engine.validators import (
    ValidationError,
    validate_ip,
    validate_cidr,
    validate_port,
    validate_protocol,
    validate_port_protocol,
    validate_bandwidth,
    validate_interface,
    validate_direction,
)


@pytest.mark.parametrize("validator,value,expected", [
    (validate_ip, "172.30.50.20", "172.30.50.20"),
    (validate_ip, "2001:0db8::1", "2001:db8::1"),
    (validate_cidr, "172.30.50.0/24", "172.30.50.0/24"),
    (validate_cidr, "2001:db8::/64", "2001:db8::/64"),
    (validate_port, 1, 1),
    (validate_port, 65535, 65535),
    (validate_protocol, "TCP", "tcp"),
    (validate_protocol, "icmp", "icmp"),
    (validate_port_protocol, "UDP", "udp"),
    (validate_bandwidth, 5, 5.0),
    (validate_bandwidth, 2.5, 2.5),
    (validate_interface, "eth0", "eth0"),
    (validate_interface, "enp1s0.100", "enp1s0.100"),
    (validate_direction, "input", "INPUT"),
    (validate_direction, "OUTPUT", "OUTPUT"),
    (validate_direction, "FORWARD", "FORWARD"),
])
def test_valid_values(validator, value, expected):
    assert validator(value) == expected


@pytest.mark.parametrize("validator,value", [
    (validate_ip, "999.1.2.3"),
    (validate_ip, "172.30.50.20;id"),
    (validate_ip, "example.com"),
    (validate_ip, "172.30.50.20/24"),
    (validate_ip, "fe80::1%eth0"),
    (validate_ip, 1234),
    (validate_cidr, "172.30.50.20/24"),
    (validate_cidr, "172.30.50.0/33"),
    (validate_cidr, "2001:db8::/129"),
    (validate_cidr, "172.30.50.0"),
    (validate_port, 0),
    (validate_port, 65536),
    (validate_port, True),
    (validate_port, "23"),
    (validate_port, 23.5),
    (validate_protocol, "tcp;id"),
    (validate_protocol, "sctp"),
    (validate_port_protocol, "icmp"),
    (validate_bandwidth, 0),
    (validate_bandwidth, -5),
    (validate_bandwidth, float("nan")),
    (validate_bandwidth, float("inf")),
    (validate_bandwidth, True),
    (validate_bandwidth, "5mbit"),
    (validate_interface, "-eth0"),
    (validate_interface, "eth0;id"),
    (validate_interface, "a" * 16),
    (validate_direction, "PREROUTING"),
    (validate_direction, "INPUT;id"),
])
def test_invalid_values(validator, value):
    with pytest.raises(ValidationError):
        validator(value)
