from unittest.mock import patch

import pytest

from src.engine.bandwidth_commands import (
    add_root,
    delete_class,
    delete_filter,
    set_class,
    set_filter,
    show_qdiscs,
)
from src.engine.command_runner import CommandRunner
from src.engine.validators import ValidationError


def test_class_sets_rate_and_ceiling():
    argv = set_class("eth0", 10, 5).argv
    assert argv[argv.index("rate") + 1] == "5mbit"
    assert argv[argv.index("ceil") + 1] == "5mbit"
    assert argv[argv.index("classid") + 1] == "1:a"


def test_filter_matches_one_ipv4_host():
    argv = set_filter("eth0", 10, "172.30.50.20").argv
    assert argv[argv.index("dst_ip") + 1] == "172.30.50.20/32"
    assert argv[argv.index("protocol") + 1] == "ip"
    assert argv[argv.index("classid") + 1] == "1:a"


def test_filter_matches_one_ipv6_host():
    argv = set_filter("eth0", 10, "2001:db8::1").argv
    assert argv[argv.index("dst_ip") + 1] == "2001:db8::1/128"
    assert argv[argv.index("protocol") + 1] == "ipv6"


def test_hosts_have_distinct_classes_and_filters():
    first = set_filter("eth0", 10, "172.30.50.20").argv
    second = set_filter("eth0", 11, "172.30.50.30").argv
    assert first[first.index("classid") + 1] != (
        second[second.index("classid") + 1]
    )
    assert first[first.index("handle") + 1] != (
        second[second.index("handle") + 1]
    )


def test_removal_targets_one_class_and_filter():
    class_command = delete_class("eth0", 10).argv
    filter_command = delete_filter("eth0", 10).argv

    assert class_command[class_command.index("classid") + 1] == "1:a"
    assert filter_command[filter_command.index("handle") + 1] == "10"
    assert "qdisc" not in class_command
    assert "qdisc" not in filter_command


def test_root_uses_add_not_replace():
    argv = add_root("eth0").argv
    assert argv[2] == "add"
    assert "replace" not in argv
    assert argv[argv.index("default") + 1] == "0"


@pytest.mark.parametrize("interface", [
    "eth0;id",
    "$(id)",
    "-eth0",
    "a" * 16,
])
def test_unsafe_interface_rejected(interface):
    with pytest.raises(ValidationError):
        show_qdiscs(interface)


@pytest.mark.parametrize("ip", [
    "172.30.50.20;id",
    "999.1.2.3",
    "172.30.50.0/24",
])
def test_invalid_host_rejected(ip):
    with pytest.raises(ValidationError):
        set_filter("eth0", 10, ip)


@pytest.mark.parametrize("class_id", [
    0, -1, 65535, True, "10", 1.5,
])
def test_invalid_class_id_rejected(class_id):
    with pytest.raises(ValueError):
        set_class("eth0", class_id, 5)


@pytest.mark.parametrize("rate", [
    0, -1, float("nan"), float("inf"), True, "5;id",
])
def test_invalid_rate_rejected(rate):
    with pytest.raises(ValidationError):
        set_class("eth0", 10, rate)


def test_bandwidth_dry_run_launches_nothing():
    with patch("src.engine.command_runner.subprocess.run") as launch:
        result = CommandRunner("dry-run").run(
            set_class("eth0", 10, 5)
        )

    launch.assert_not_called()
    assert result["status"] == "dry-run"
    assert result["executed"] is False
