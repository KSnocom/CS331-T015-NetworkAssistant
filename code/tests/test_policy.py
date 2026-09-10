import pytest

from src.engine.policy_engine import PolicyDenied, PolicyEngine
from src.engine.validators import ValidationError


@pytest.fixture
def policy():
    return PolicyEngine()


def test_client_ip_approved(policy):
    assert policy.check_ip("172.30.50.20") == {
        "ip_address": "172.30.50.20",
        "direction": "INPUT",
    }


def test_port_23_approved(policy):
    result = policy.check_port(23, "TCP")
    assert result["port"] == 23
    assert result["protocol"] == "tcp"


@pytest.mark.parametrize("port", [22, 443])
def test_protected_ports_rejected(policy, port):
    with pytest.raises(PolicyDenied):
        policy.check_port(port, "tcp")


@pytest.mark.parametrize("ip", ["172.30.50.1", "172.30.50.10"])
def test_protected_hosts_rejected(policy, ip):
    with pytest.raises(PolicyDenied):
        policy.check_ip(ip)
    with pytest.raises(PolicyDenied):
        policy.check_bandwidth(ip, 5)


def test_five_mbps_approved(policy):
    assert policy.check_bandwidth("172.30.50.20", 5) == {
        "ip_address": "172.30.50.20",
        "interface": "eth0",
        "rate_mbps": 5.0,
    }


@pytest.mark.parametrize("rate", [0.5, 1001])
def test_rates_outside_policy_rejected(policy, rate):
    with pytest.raises(PolicyDenied):
        policy.check_bandwidth("172.30.50.20", rate)


def test_zero_rate_invalid(policy):
    with pytest.raises(ValidationError):
        policy.check_bandwidth("172.30.50.20", 0)


@pytest.mark.parametrize("ip", ["8.8.8.8", "127.0.0.1", "2001:db8::1"])
def test_outside_lab_rejected(policy, ip):
    with pytest.raises(PolicyDenied):
        policy.check_ip(ip)
    with pytest.raises(PolicyDenied):
        policy.check_bandwidth(ip, 5)
    with pytest.raises(PolicyDenied):
        policy.check_target(ip)


def test_invalid_ip_rejected(policy):
    with pytest.raises(ValidationError):
        policy.check_ip("999.1.2.3")


def test_bandwidth_removal_approved(policy):
    result = policy.check_bandwidth("172.30.50.20")
    assert "rate_mbps" not in result


def test_rule_capacity(policy):
    policy.check_rule_capacity(99)
    with pytest.raises(PolicyDenied):
        policy.check_rule_capacity(100)


def test_icmp_port_rule_rejected(policy):
    with pytest.raises(ValidationError):
        policy.check_port(23, "icmp")
