import json
import subprocess
from unittest.mock import patch

import pytest

from src.engine.audit import AuditLogger
from src.engine.command_builder import (
    Command,
    firewall_ip_rule,
    firewall_port_rule,
    show_firewall_rules,
)
from src.engine.command_runner import CommandRunner
from src.engine.validators import ValidationError


def test_ip_rule_has_exact_arguments():
    command = firewall_ip_rule("add", "172.30.50.20")
    assert command.argv == (
        "/usr/sbin/iptables", "-w", "5",
        "-I", "INPUT", "1",
        "-s", "172.30.50.20",
        "-m", "comment", "--comment", "ina-v1-ip",
        "-j", "DROP",
    )


def test_output_matches_destination():
    argv = firewall_ip_rule("add", "172.30.50.20", "OUTPUT").argv
    assert "-d" in argv
    assert "-s" not in argv


def test_ipv6_uses_ip6tables():
    assert firewall_ip_rule("add", "2001:db8::1").argv[0] == (
        "/usr/sbin/ip6tables"
    )


def test_port_rule():
    argv = firewall_port_rule("add", 23, "TCP").argv
    assert argv[argv.index("-p") + 1] == "tcp"
    assert argv[argv.index("--dport") + 1] == "23"


def test_deletion_matches_added_rule():
    added = firewall_port_rule("add", 23, "tcp").argv
    deleted = firewall_port_rule("delete", 23, "tcp").argv
    assert deleted[3:5] == ("-D", "INPUT")
    assert added[6:] == deleted[5:]


def test_arbitrary_operation_rejected():
    with pytest.raises(ValueError):
        firewall_ip_rule("flush", "172.30.50.20")


def test_injected_address_rejected():
    with pytest.raises(ValidationError):
        firewall_ip_rule("add", "172.30.50.20;id")


def test_icmp_port_rejected():
    with pytest.raises(ValidationError):
        firewall_port_rule("add", 23, "icmp")


def test_dry_run_never_launches_subprocess():
    with patch("src.engine.command_runner.subprocess.run") as launch:
        result = CommandRunner().run(show_firewall_rules())

    launch.assert_not_called()
    assert result["status"] == "dry-run"
    assert result["executed"] is False
    assert result["return_code"] is None


def test_shell_executable_rejected():
    with pytest.raises(ValueError):
        CommandRunner().run(Command(("/bin/sh", "-c", "id")))


def test_live_runner_captures_failure_without_shell():
    completed = subprocess.CompletedProcess(
        args=[], returncode=2, stdout="", stderr="example failure"
    )

    with patch(
        "src.engine.command_runner.subprocess.run",
        return_value=completed,
    ) as launch:
        result = CommandRunner("live").run(show_firewall_rules())

    assert launch.call_args.kwargs["shell"] is False
    assert isinstance(launch.call_args.args[0], list)
    assert result["status"] == "failed"
    assert result["return_code"] == 2
    assert result["stderr"] == "example failure"


def test_timeout_is_recorded():
    error = subprocess.TimeoutExpired(
        cmd=["iptables"], timeout=10, output=b"partial output"
    )

    with patch(
        "src.engine.command_runner.subprocess.run",
        side_effect=error,
    ):
        result = CommandRunner("live").run(show_firewall_rules())

    assert result["status"] == "timeout"
    assert result["return_code"] is None
    assert result["stdout"] == "partial output"


def test_audit_appends_valid_json_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    event = {
        "action": "BLOCK_PORT",
        "parameters": {"port": 23, "protocol": "tcp"},
        "policy_result": "approved",
        "execution_result": "dry-run",
        "validation_result": "not_run",
    }

    logger.write(event)
    logger.write(event)

    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(records) == 2
    assert records[0]["parameters"]["port"] == 23
    assert records[0]["execution_result"] == "dry-run"
    assert "timestamp" in records[0]


def test_incomplete_audit_event_rejected(tmp_path):
    path = tmp_path / "audit.jsonl"

    with pytest.raises(ValueError):
        AuditLogger(path).write({"action": "BLOCK_PORT"})

    assert not path.exists()
