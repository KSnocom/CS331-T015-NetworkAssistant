"""Bounded, policy-controlled monitoring."""

import json
import uuid

from src.engine.audit import AuditLogger
from src.engine.command_runner import CommandRunner
from src.engine.monitoring_commands import ping_command, iperf_command
from src.engine.policy_engine import PolicyDenied, PolicyEngine
from src.engine.validators import ValidationError


class MonitoringService:
    def __init__(self, mode="dry-run", policy=None, runner=None, audit=None):
        self.policy = policy if policy is not None else PolicyEngine()
        self.runner = runner if runner is not None else CommandRunner(mode)
        self.audit = audit if audit is not None else AuditLogger()

    def _read(self, action, parameters, build, parse=None):
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
            planned = build()
            result["policy_result"] = "approved"
            outputs = []

            for command in planned:
                execution = self.runner.run(command)
                result["commands"].append(execution)

                if self.runner.mode == "live":
                    if (
                        execution["status"] != "success"
                        or execution["return_code"] != 0
                    ):
                        result["execution_result"] = "failed"
                        raise RuntimeError(
                            execution.get("error")
                            or execution.get("stderr")
                            or execution.get("stdout")
                            or "Monitoring command failed"
                        )
                    outputs.append(execution["stdout"])

            if self.runner.mode == "dry-run":
                result.update(
                    status="dry-run",
                    execution_result="dry-run",
                )
            else:
                result["execution_result"] = "success"
                result["validation_result"] = "fail"
                result["data"] = parse(outputs) if parse else outputs
                result.update(status="success", validation_result="pass")

        except PolicyDenied as exc:
            result.update(
                status="rejected", policy_result="denied", message=str(exc)
            )
        except ValidationError as exc:
            result.update(
                status="invalid",
                validation_result="invalid_input",
                message=str(exc),
            )
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
            result.update(status="error", message=str(exc))

        try:
            self.audit.write({**result, "phase": "result"})
        except (OSError, ValueError) as exc:
            result["operation_status"] = result["status"]
            result["status"] = "audit_error"
            result["audit_error"] = str(exc)

        return result

    def ping_host(self, ip_address):
        return self._read(
            "PING_HOST",
            {"ip_address": ip_address},
            lambda: [ping_command(self.policy.check_target(ip_address))],
        )

    def validate_bandwidth(self, ip_address, duration_seconds=10):
        def parse(outputs):
            report = json.loads(outputs[0])
            if "error" in report:
                raise RuntimeError(report["error"])

            receiver_bps = report["end"]["sum_received"]["bits_per_second"]
            return {
                "receiver_mbps": receiver_bps / 1_000_000,
                "iperf3": report,
            }

        return self._read(
            "VALIDATE_BANDWIDTH",
            {
                "ip_address": ip_address,
                "duration_seconds": duration_seconds,
            },
            lambda: [
                iperf_command(
                    self.policy.check_target(ip_address), duration_seconds
                )
            ],
            parse,
        )
