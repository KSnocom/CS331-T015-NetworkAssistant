"""Non-functional checks through real MCP sessions."""

import argparse
import asyncio
import json
import math
import statistics
import time
from contextlib import AsyncExitStack
from datetime import datetime, timezone
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


ROOT = Path(__file__).resolve().parents[1]


async def run(args):
    checks = []
    events = []
    timings = {
        "repeat_no_change_ms": [],
        "block_change_ms": [],
        "allow_change_ms": [],
    }
    failures = []
    cleanup_needed = False

    def check(name, condition, detail=""):
        checks.append({
            "name": name,
            "passed": bool(condition),
            "detail": detail,
        })
        if not condition:
            raise AssertionError(name + ": " + detail)

    parameters = StdioServerParameters(
        command="docker",
        args=[
            "compose", "-f", str(ROOT / "docker/docker-compose.yml"),
            "exec", "-T", "admin",
            "python3", "-m", "src.server", "--mode", "live",
        ],
    )

    async with AsyncExitStack() as stack:
        sessions = []

        # Two independent server processes exercise the shared file lock.
        for _ in range(2):
            read, write = await stack.enter_async_context(
                stdio_client(parameters)
            )
            session = await stack.enter_async_context(
                ClientSession(read, write)
            )
            await session.initialize()
            sessions.append(session)

        async def call(tool, arguments=None, session_index=0):
            started = time.perf_counter()
            response = await sessions[session_index].call_tool(
                tool, arguments or {}
            )
            elapsed_ms = (time.perf_counter() - started) * 1000

            payload = response.structuredContent
            if payload is None:
                text = "\n".join(
                    item.text for item in response.content
                    if item.type == "text"
                )
                try:
                    payload = json.loads(text)
                except ValueError:
                    payload = {"message": text}

            if not isinstance(payload, dict):
                payload = {"data": payload}

            if response.isError:
                payload = {**payload, "status": "mcp_error"}

            events.append({
                "tool": tool,
                "arguments": arguments or {},
                "elapsed_ms": elapsed_ms,
                "result": payload,
            })
            return payload, elapsed_ms

        port = {"port": 23, "protocol": "tcp"}

        try:
            print("[1/6] Checking tool surface and clean starting state")

            tools = await sessions[0].list_tools()
            expected = {
                "block_ip", "allow_ip", "block_port", "allow_port",
                "limit_bandwidth", "remove_bandwidth_limit",
                "ping_host", "validate_bandwidth",
                "show_firewall_rules", "show_bandwidth_rules",
            }
            check(
                "Only the ten approved tools are exposed",
                {item.name for item in tools.tools} == expected,
            )

            initial, _ = await call("show_firewall_rules")
            check("Initial inspection succeeds", initial["status"] == "success")
            check(
                "No existing assistant firewall rules",
                "ina-v1-" not in initial["data"]["ipv4"]
                and "ina-v1-" not in initial["data"]["ipv6"],
                "The suite requires an empty managed-firewall baseline.",
            )

            print("[2/6] Testing validation and policy rejection")

            cases = [
                (
                    "Protected port rejected",
                    "block_port",
                    {"port": 22, "protocol": "tcp"},
                    "rejected",
                ),
                (
                    "Command-like IP rejected",
                    "block_ip",
                    {"ip_address": "172.30.50.20;id"},
                    "invalid",
                ),
                (
                    "Outside-lab target rejected",
                    "block_ip",
                    {"ip_address": "8.8.8.8"},
                    "rejected",
                ),
            ]

            for name, tool, arguments, expected_status in cases:
                result, _ = await call(tool, arguments)
                check(
                    name,
                    result.get("status") == expected_status
                    and result.get("commands") == [],
                    "Rejected requests must execute no commands.",
                )

            result, _ = await call(
                "block_port", {"port": True, "protocol": "tcp"}
            )
            check(
                "MCP schema rejects a Boolean port",
                result.get("status") == "mcp_error",
            )

            print("[3/6] Testing repeat requests and measuring latency")

            cleanup_needed = True
            result, _ = await call("block_port", port)
            check(
                "Initial block succeeds",
                result.get("status") == "success"
                and result.get("execution_result") == "success",
            )

            for _ in range(args.samples):
                result, elapsed = await call("block_port", port)
                if not (
                    result.get("status") == "success"
                    and result.get("execution_result") == "no_change"
                    and result.get("validation_result") == "pass"
                ):
                    raise AssertionError("Repeated block changed state or failed")
                timings["repeat_no_change_ms"].append(elapsed)

            check("Repeated blocks make no additional changes", True)

            result, _ = await call("allow_port", port)
            check("Block removed before concurrency test",
                  result.get("status") == "success")

            print("[4/6] Sending eight concurrent calls across two servers")

            started = time.perf_counter()
            concurrent = await asyncio.gather(*[
                call("block_port", port, index % 2)
                for index in range(8)
            ])
            concurrency_ms = (time.perf_counter() - started) * 1000

            results = [item[0] for item in concurrent]
            changes = sum(
                item.get("execution_result") == "success"
                for item in results
            )
            unchanged = sum(
                item.get("execution_result") == "no_change"
                for item in results
            )

            check(
                "Concurrent requests produce one change and seven no-ops",
                all(item.get("status") == "success" for item in results)
                and changes == 1 and unchanged == 7,
                f"Batch duration: {concurrency_ms:.2f} ms",
            )

            inspection, _ = await call("show_firewall_rules")
            matching_rows = [
                line for line in inspection["data"]["ipv4"].splitlines()
                if "ina-v1-port" in line and "dpt:23" in line
            ]
            check("Exactly one port-23 rule exists", len(matching_rows) == 1)

            result, _ = await call("allow_port", port)
            check("Concurrent-test rule removed",
                  result.get("status") == "success")

            for _ in range(args.samples):
                result, elapsed = await call("block_port", port)
                if not (
                    result.get("status") == "success"
                    and result.get("execution_result") == "success"
                ):
                    raise AssertionError("Measured block did not apply")
                timings["block_change_ms"].append(elapsed)

                result, elapsed = await call("allow_port", port)
                if not (
                    result.get("status") == "success"
                    and result.get("execution_result") == "success"
                ):
                    raise AssertionError("Measured removal did not apply")
                timings["allow_change_ms"].append(elapsed)

            check("Repeated apply/remove cycles succeed", True)

            print("[5/6] Testing a bounded failed connectivity probe")

            # This address is unassigned in the supplied three-container lab.
            result, elapsed = await call(
                "ping_host", {"ip_address": "172.30.50.254"}
            )
            check(
                "Unreachable probe returns a bounded failure",
                result.get("status") == "error"
                and result.get("execution_result") == "failed"
                and elapsed <= 12000,
                f"Elapsed: {elapsed:.2f} ms; project budget: 12000 ms",
            )

        except Exception as exc:
            failures.append(str(exc))

        finally:
            if cleanup_needed:
                try:
                    # Retry only to remove duplicate exact rules if a test
                    # exposed an idempotency defect.
                    for _ in range(10):
                        result, _ = await call("allow_port", port)
                        if result.get("status") == "success":
                            break

                    check(
                        "Final cleanup request succeeds",
                        result.get("status") == "success",
                    )

                    final, _ = await call("show_firewall_rules")
                    check(
                        "Final managed firewall state is empty",
                        final.get("status") == "success"
                        and "ina-v1-" not in final["data"]["ipv4"]
                        and "ina-v1-" not in final["data"]["ipv6"],
                    )
                except Exception as exc:
                    failures.append("Cleanup: " + str(exc))

    print("[6/6] Checking audit coverage and writing reports")

    try:
        returned = {
            event["result"]["request_id"]: event["result"]
            for event in events
            if "request_id" in event["result"]
        }
        logged = {}
        with (ROOT / "logs/audit.jsonl").open() as stream:
            for line in stream:
                item = json.loads(line)
                request_id = item.get("request_id")
                if item.get("phase") == "result" and request_id in returned:
                    logged.setdefault(request_id, []).append(item)

        required = {
            "timestamp", "action", "parameters", "policy_result",
            "execution_result", "validation_result", "commands",
        }
        valid = True
        for request_id, result in returned.items():
            records = logged.get(request_id, [])
            if len(records) != 1:
                valid = False
                continue
            record = records[0]
            if (
                not required.issubset(record)
                or record["status"] != result["status"]
                or record["commands"] != result["commands"]
            ):
                valid = False

        check(
            "Every application response has one matching final audit record",
            bool(returned) and valid,
            f"Checked {len(returned)} application request IDs.",
        )
    except Exception as exc:
        failures.append("Audit: " + str(exc))

    metrics = {}
    for name, values in timings.items():
        if values:
            ordered = sorted(values)
            metrics[name] = {
                "samples": len(values),
                "median_ms": round(statistics.median(values), 3),
                "p95_ms": round(ordered[math.ceil(0.95 * len(ordered)) - 1], 3),
                "maximum_ms": round(max(values), 3),
            }

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "FAIL" if failures else "PASS",
        "checks": checks,
        "latency": metrics,
        "failures": failures,
        "scope": (
            "Live MCP requests, including policy, kernel commands, and audit. "
            "Excludes server startup and LLM/Ollama processing."
        ),
        "limitations": [
            "Latency is measured, not graded against an approved requirement.",
            "Schema-level rejection is captured in client evidence, not the "
            "application audit, because the tool body is not invoked.",
            "This run does not test maximum rule capacity or crash recovery.",
        ],
    }

    (ROOT / "docs").mkdir(exist_ok=True)
    (ROOT / "logs").mkdir(exist_ok=True)

    (ROOT / "docs/nfr-results.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (ROOT / "logs/nfr-client-events.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )

    lines = [
        "# Non-functional test results",
        "",
        f"Overall: **{report['status']}**",
        "",
        report["scope"],
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
    ]
    for item in checks:
        detail = item["detail"].replace("|", "/").replace("\n", " ")
        lines.append(
            f"| {item['name']} | {'PASS' if item['passed'] else 'FAIL'} "
            f"| {detail} |"
        )

    lines.extend([
        "",
        "| Operation | Samples | Median ms | P95 ms | Maximum ms |",
        "|---|---:|---:|---:|---:|",
    ])
    for name, metric in metrics.items():
        lines.append(
            f"| {name} | {metric['samples']} | {metric['median_ms']} "
            f"| {metric['p95_ms']} | {metric['maximum_ms']} |"
        )

    lines.extend(["", "## Limitations", ""])
    lines.extend("- " + item for item in report["limitations"])
    if failures:
        lines.extend(["", "## Failures", ""])
        lines.extend("- " + item for item in failures)

    (ROOT / "docs/nfr-results.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )

    print(json.dumps(report, indent=2))
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=20)
    args = parser.parse_args()
    if not 5 <= args.samples <= 100:
        parser.error("--samples must be between 5 and 100")
    raise SystemExit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
