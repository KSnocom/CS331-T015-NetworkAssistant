"""Policy-controlled bandwidth operations with persistent ownership."""

import ipaddress
import json
import os
import uuid
from pathlib import Path

from src.engine import bandwidth_commands as commands
from src.engine.audit import AuditLogger
from src.engine.bandwidth_state import BandwidthState
from src.engine.command_runner import CommandRunner
from src.engine.policy_engine import PolicyDenied, PolicyEngine
from src.engine.validators import ValidationError


class BandwidthService:
    def __init__(
        self, mode="dry-run", policy=None, runner=None, audit=None, state=None
    ):
        self.policy = policy if policy is not None else PolicyEngine()
        self.runner = runner if runner is not None else CommandRunner(mode)
        self.audit = audit if audit is not None else AuditLogger()
        self.state = state if state is not None else BandwidthState()

    def limit_bandwidth(self, ip_address, rate_mbps):
        return self._change(ip_address, rate_mbps, removing=False)

    def remove_bandwidth_limit(self, ip_address):
        return self._change(ip_address, None, removing=True)

    def _run(self, command, result):
        execution = self.runner.run(command)
        result["commands"].append(execution)
        if (
            execution["status"] != "success"
            or execution["return_code"] != 0
        ):
            raise RuntimeError(
                execution.get("error")
                or execution.get("stderr")
                or "Network command failed"
            )
        return execution["stdout"]

    def _mutate(self, command, result):
        result["execution_result"] = "attempted"
        return self._run(command, result)

    def _read_json(self, command, result):
        data = json.loads(self._run(command, result))
        if not isinstance(data, list):
            raise RuntimeError("Unexpected tc JSON output")
        return data

    def _snapshot(self, interface, result):
        qdiscs = self._read_json(commands.show_qdiscs(interface), result)
        roots = [item for item in qdiscs if item.get("root") is True]

        if len(roots) != 1:
            raise RuntimeError("Expected exactly one root scheduler")

        root = roots[0]
        classes = []
        filters = []

        if root.get("kind") == "htb" and root.get("handle") == "1:":
            classes = self._read_json(
                commands.show_classes(interface), result
            )
            filters = self._read_json(
                commands.show_filters(interface), result
            )
            # tc also emits filter headers without rule options.
            filters = [item for item in filters if "options" in item]

        return root, classes, filters

    @staticmethod
    def _context(interface):
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        namespace = os.readlink("/proc/self/ns/net")
        index = Path(f"/sys/class/net/{interface}/ifindex").read_text().strip()
        return f"{boot}|{namespace}|{interface}|{index}"

    @staticmethod
    def _handle(record):
        return f"1:{record['class_id']:x}"

    @staticmethod
    def _number(value):
        if type(value) is int:
            return value
        if isinstance(value, str):
            return int(value, 0)
        raise ValueError("Unexpected tc numeric field")

    def _filter_matches(self, item, ip, record):
        try:
            options = item["options"]
            destination = ipaddress.ip_network(
                options["keys"]["dst_ip"], strict=False
            )
            return (
                item.get("kind") == "flower"
                and item.get("chain", 0) == 0
                and item["pref"] == record["class_id"]
                and self._number(options["handle"]) == record["class_id"]
                and options["classid"] == self._handle(record)
                and destination.num_addresses == 1
                and destination.network_address == ipaddress.ip_address(ip)
            )
        except (KeyError, TypeError, ValueError):
            return False

    def _check_ownership(self, data, snapshot, context):
        root, classes, filters = snapshot

        if data["context"] not in {None, context}:
            raise RuntimeError(
                "Stored state belongs to a different network context. "
                "Stop and reconcile state after container recreation."
            )

        if root.get("kind") == "noqueue":
            if data["root_owned"] or data["hosts"]:
                raise RuntimeError(
                    "Stored bandwidth state disagrees with the kernel."
                )
            return False

        if not (
            root.get("kind") == "htb"
            and root.get("handle") == "1:"
            and data["root_owned"]
            and data["context"] == context
        ):
            raise RuntimeError("Refusing to modify an unowned root scheduler")

        expected = {
            self._handle(record) for record in data["hosts"].values()
        }

        for item in classes:
            if item.get("class", item.get("kind")) != "htb" or item.get("handle") not in expected:
                raise RuntimeError("Unrecognized class in the shared scheduler")

        for item in filters:
            if not any(
                self._filter_matches(item, ip, record)
                for ip, record in data["hosts"].items()
            ):
                raise RuntimeError("Unrecognized filter in the shared scheduler")

        return True

    def _verified_limit(self, snapshot, ip, record):
        _, classes, filters = snapshot
        matching_classes = [
            item for item in classes
            if item.get("handle") == self._handle(record)
        ]
        matching_filters = [
            item for item in filters if self._filter_matches(item, ip, record)
        ]

        if len(matching_classes) != 1 or len(matching_filters) != 1:
            return False

        try:
            options = matching_classes[0].get("options", matching_classes[0])
            # tc JSON represents HTB rate and ceil in bytes per second.
            expected = record["rate_mbps"] * 1_000_000 / 8
            tolerance = max(1, expected * 0.000001)
            return (
                abs(float(options["rate"]) - expected) <= tolerance
                and abs(float(options["ceil"]) - expected) <= tolerance
            )
        except (KeyError, TypeError, ValueError):
            return False

    def _dry_run(self, transaction, approved, removing, result):
        ip = approved["ip_address"]
        interface = approved["interface"]
        planned = []

        if removing:
            record = transaction.data["hosts"].get(ip)
            if record is not None:
                class_id = record["class_id"]
                family = ipaddress.ip_address(ip).version
                planned = [
                    commands.delete_filter(interface, class_id, family),
                    commands.delete_class(interface, class_id),
                ]
        else:
            class_id = transaction.reserve_host(ip, approved["rate_mbps"])
            if not transaction.data["root_owned"]:
                planned.append(commands.add_root(interface))
            planned.extend([
                commands.set_class(interface, class_id, approved["rate_mbps"]),
                commands.set_filter(interface, class_id, ip),
            ])

        result["commands"] = [self.runner.run(item) for item in planned]
        result.update(
            status="dry-run",
            execution_result="dry-run",
            message=(
                "Conditional plan based on stored assignments. Kernel state "
                "and ownership have not been checked. No assignments saved."
            ),
        )

    def _live(self, transaction, approved, removing, result):
        data = transaction.data
        ip = approved["ip_address"]
        interface = approved["interface"]
        context = self._context(interface)
        snapshot = self._snapshot(interface, result)
        owned = self._check_ownership(data, snapshot, context)
        record = data["hosts"].get(ip)

        if removing and record is None:
            result.update(
                status="success",
                execution_result="no_change",
                validation_result="pass",
                message="No managed limit exists for this host.",
            )
            return

        if (
            not removing
            and record is not None
            and record["phase"] == "active"
            and record["rate_mbps"] == approved["rate_mbps"]
            and self._verified_limit(snapshot, ip, record)
        ):
            result.update(
                status="success",
                execution_result="no_change",
                validation_result="pass",
            )
            return

        # If this write fails, no network mutation starts.
        self.audit.write({
            **result, "phase": "intent", "execution_result": "pending"
        })

        if removing:
            record["phase"] = "removing"
            transaction.save()
            class_id = record["class_id"]
            family = ipaddress.ip_address(ip).version

            if any(
                self._filter_matches(item, ip, record)
                for item in snapshot[2]
            ):
                self._mutate(
                    commands.delete_filter(interface, class_id, family), result
                )

            snapshot = self._snapshot(interface, result)
            if any(
                self._filter_matches(item, ip, record)
                for item in snapshot[2]
            ):
                raise RuntimeError("Filter removal was not verified")

            if any(
                item.get("handle") == self._handle(record)
                for item in snapshot[1]
            ):
                self._mutate(
                    commands.delete_class(interface, class_id), result
                )

            snapshot = self._snapshot(interface, result)
            result["validation_result"] = "fail"

            if any(
                item.get("handle") == self._handle(record)
                for item in snapshot[1]
            ) or any(
                self._filter_matches(item, ip, record)
                for item in snapshot[2]
            ):
                raise RuntimeError("Bandwidth removal was not verified")

            del data["hosts"][ip]
            transaction.save()

        else:
            if not owned:
                data["context"] = context
                transaction.save()
                self._mutate(commands.add_root(interface), result)
                data["root_owned"] = True
                transaction.save()

            class_id = transaction.reserve_host(ip, approved["rate_mbps"])
            transaction.save()
            record = data["hosts"][ip]

            self._mutate(
                commands.set_class(interface, class_id, approved["rate_mbps"]),
                result,
            )
            self._mutate(
                commands.set_filter(interface, class_id, ip), result
            )

            snapshot = self._snapshot(interface, result)
            result["validation_result"] = "fail"

            if not self._verified_limit(snapshot, ip, record):
                raise RuntimeError(
                    "Rate/filter verification failed. Inspect tc JSON "
                    "and saved pending state before continuing."
                )

            record["phase"] = "active"
            transaction.save()

        result.update(
            status="success",
            execution_result="success",
            validation_result="pass",
            message="Requested bandwidth state verified in the kernel.",
        )

    def _change(self, ip_address, rate_mbps, removing):
        parameters = {"ip_address": ip_address}
        if not removing:
            parameters["rate_mbps"] = rate_mbps

        result = {
            "request_id": str(uuid.uuid4()),
            "action": "REMOVE_BANDWIDTH_LIMIT" if removing else "LIMIT_BANDWIDTH",
            "parameters": parameters,
            "mode": self.runner.mode,
            "status": "error",
            "policy_result": "not_checked",
            "execution_result": "not_run",
            "validation_result": "not_run",
            "commands": [],
        }

        try:
            if not removing and rate_mbps is None:
                raise ValidationError("A bandwidth rate is required")

            approved = self.policy.check_bandwidth(ip_address, rate_mbps)
            result["parameters"] = approved
            result["policy_result"] = "approved"

            with self.state.locked() as transaction:
                if self.runner.mode == "dry-run":
                    self._dry_run(transaction, approved, removing, result)
                else:
                    self._live(transaction, approved, removing, result)

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
            if result["execution_result"] == "attempted":
                result["execution_result"] = "failed_or_partial"
            result.update(status="error", message=str(exc))

        try:
            self.audit.write({**result, "phase": "result"})
        except (OSError, ValueError) as exc:
            result["operation_status"] = result["status"]
            result["status"] = "audit_error"
            result["audit_error"] = str(exc)

        return result
