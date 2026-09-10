"""Constrained firewall operations; no arbitrary command interface."""

import fcntl
import shlex
import uuid

from src.engine.audit import AuditLogger
from src.engine.command_builder import (
    firewall_ip_rule,
    firewall_port_rule,
    list_firewall_rules,
)
from src.engine.command_runner import CommandRunner
from src.engine.policy_engine import PolicyDenied, PolicyEngine
from src.engine.validators import ValidationError


class FirewallService:
    def __init__(self, mode="dry-run", policy=None, runner=None, audit=None):
        self.policy = policy if policy is not None else PolicyEngine()
        self.runner = runner if runner is not None else CommandRunner(mode)
        self.audit = audit if audit is not None else AuditLogger()

    def block_ip(self, ip_address, direction="INPUT"):
        return self._change(
            "BLOCK_IP",
            {"ip_address": ip_address, "direction": direction},
        )

    def allow_ip(self, ip_address, direction="INPUT"):
        return self._change(
            "ALLOW_IP",
            {"ip_address": ip_address, "direction": direction},
        )

    def block_port(self, port, protocol, direction="INPUT"):
        return self._change(
            "BLOCK_PORT",
            {"port": port, "protocol": protocol, "direction": direction},
        )

    def allow_port(self, port, protocol, direction="INPUT"):
        return self._change(
            "ALLOW_PORT",
            {"port": port, "protocol": protocol, "direction": direction},
        )

    def _change(self, action, parameters):
        result = {
            "request_id": str(uuid.uuid4()),
            "action": action,
            "parameters": parameters,
            "mode": self.runner.mode,
            "status": "error",
            "policy_result": "not_checked",
            "execution_result": "not_run",
            "validation_result": "not_run",
            "commands": [],
        }

        try:
            if action in {"BLOCK_IP", "ALLOW_IP"}:
                approved = self.policy.check_ip(**parameters)

                def rule(operation):
                    return firewall_ip_rule(operation, **approved)
            else:
                approved = self.policy.check_port(**parameters)

                def rule(operation):
                    # This lab's port tools operate on IPv4.
                    return firewall_port_rule(operation, **approved)

            result["parameters"] = approved
            result["policy_result"] = "approved"
            blocking = action.startswith("BLOCK")
            operation = "add" if blocking else "delete"

            if self.runner.mode == "dry-run":
                result["commands"] = [
                    self.runner.run(rule(operation)),
                    self.runner.run(rule("check")),
                ]
                result.update(
                    status="dry-run",
                    execution_result="dry-run",
                    message=(
                        "Plan only. Current rules, capacity, and resulting "
                        "kernel state have not been checked."
                    ),
                )
            else:
                # Serialize cooperating CLI/MCP processes in this container.
                lock_path = self.audit.path.parent / "firewall.lock"
                lock_path.parent.mkdir(parents=True, exist_ok=True)

                with lock_path.open("a", encoding="utf-8") as lock:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                    try:
                        self._live_change(result, rule, blocking, operation)
                    finally:
                        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

        except PolicyDenied as exc:
            result.update(
                status="rejected",
                policy_result="denied",
                message=str(exc),
            )
        except ValidationError as exc:
            result.update(
                status="invalid",
                validation_result="invalid_input",
                message=str(exc),
            )
        except (OSError, RuntimeError, ValueError) as exc:
            result.update(status="error", message=str(exc))

        try:
            self.audit.write({**result, "phase": "result"})
        except (OSError, ValueError) as exc:
            result["operation_status"] = result["status"]
            result["status"] = "audit_error"
            result["audit_error"] = str(exc)

        return result

    def _run(self, command, result):
        execution = self.runner.run(command)
        result["commands"].append(execution)
        return execution

    @staticmethod
    def _require_success(execution):
        if (
            execution["status"] != "success"
            or execution["return_code"] != 0
        ):
            raise RuntimeError(
                "Command failed: "
                + (execution.get("error") or execution.get("stderr")
                   or execution["status"])
            )

    def _managed_count(self, result):
        count = 0

        # Enforce a total across IPv4 and IPv6 managed firewall rules.
        for family in (4, 6):
            execution = self._run(list_firewall_rules(family), result)
            self._require_success(execution)

            for line in execution["stdout"].splitlines():
                fields = shlex.split(line)
                if not fields or fields[0] != "-A":
                    continue
                if "--comment" in fields:
                    index = fields.index("--comment") + 1
                    if index < len(fields) and fields[index] in {
                        "ina-v1-ip", "ina-v1-port"
                    }:
                        count += 1

        return count

    def _exists(self, rule, result):
        execution = self._run(rule("check"), result)

        if execution["status"] == "success" and execution["return_code"] == 0:
            return True

        # iptables -C returns 1 when a matching rule is absent.
        if execution["status"] == "failed" and execution["return_code"] == 1:
            return False

        self._require_success(execution)
        raise RuntimeError("Unexpected rule-check result")

    def _live_change(self, result, rule, blocking, operation):
        count = self._managed_count(result)
        exists = self._exists(rule, result)

        if exists == blocking:
            result.update(
                status="success",
                execution_result="no_change",
                validation_result="pass",
                message="The requested managed-rule state already exists.",
            )
            return

        if blocking:
            self.policy.check_rule_capacity(count)

        # Fail closed if the intent cannot be logged before mutation.
        self.audit.write({
            **result,
            "phase": "intent",
            "execution_result": "pending",
        })

        result["execution_result"] = "attempted"
        execution = self._run(rule(operation), result)
        if execution["status"] != "success":
            result["execution_result"] = "failed"
        self._require_success(execution)
        result["execution_result"] = "success"

        result["validation_result"] = "pending"
        verified = self._exists(rule, result) == blocking

        result.update(
            status="success" if verified else "verification_failed",
            validation_result="pass" if verified else "fail",
            message=(
                "Managed firewall rule verified."
                if verified
                else "Kernel rule state does not match the request; inspect rules."
            ),
        )
