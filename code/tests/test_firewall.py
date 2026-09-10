import json
from unittest.mock import patch

import pytest

from src.engine.audit import AuditLogger
from src.tools.firewall import FirewallService


@pytest.fixture
def firewall(tmp_path):
    return FirewallService(
        mode="dry-run",
        audit=AuditLogger(tmp_path / "audit.jsonl"),
    )


def test_approved_block_is_only_a_plan(firewall):
    with patch("src.engine.command_runner.subprocess.run") as launch:
        result = firewall.block_port(23, "tcp")

    launch.assert_not_called()
    assert result["status"] == "dry-run"
    assert result["policy_result"] == "approved"
    assert result["validation_result"] == "not_run"
    assert all(not item["executed"] for item in result["commands"])


def test_protected_port_never_reaches_runner(firewall):
    with patch.object(firewall.runner, "run") as run:
        result = firewall.block_port(22, "tcp")

    run.assert_not_called()
    assert result["status"] == "rejected"
    assert result["policy_result"] == "denied"


def test_invalid_ip_never_reaches_runner(firewall):
    with patch.object(firewall.runner, "run") as run:
        result = firewall.block_ip("999.1.2.3")

    run.assert_not_called()
    assert result["status"] == "invalid"
    assert result["validation_result"] == "invalid_input"


def test_protected_host_rejected(firewall):
    result = firewall.block_ip("172.30.50.10")
    assert result["status"] == "rejected"
    assert result["commands"] == []


def test_allow_plans_exact_deletion(firewall):
    result = firewall.allow_ip("172.30.50.20")
    argv = result["commands"][0]["command"]
    assert "-D" in argv
    assert "ina-v1-ip" in argv
    assert "ACCEPT" not in argv


def test_rejection_is_audited(firewall):
    firewall.block_port(443, "tcp")

    lines = firewall.audit.path.read_text().splitlines()
    event = json.loads(lines[-1])

    assert event["action"] == "BLOCK_PORT"
    assert event["policy_result"] == "denied"
    assert event["execution_result"] == "not_run"
    assert event["phase"] == "result"
