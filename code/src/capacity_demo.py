"""Test the configured managed-firewall rule limit through MCP."""

import asyncio
import json
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from src.engine.policy_engine import PolicyEngine


ROOT = Path(__file__).resolve().parents[1]


async def run():
    limit = PolicyEngine().max_rules
    if not 1 <= limit <= 200:
        raise ValueError("This demo supports configured limits from 1 to 200")

    checks = []
    events = []
    attempted = set()
    measurements = []
    failures = []

    def check(name, condition):
        checks.append({"name": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    parameters = StdioServerParameters(
        command="docker",
        args=[
            "compose", "-f", str(ROOT / "docker/docker-compose.yml"),
            "exec", "-T", "admin",
            "python3", "-m", "src.server", "--mode", "live",
        ],
    )

    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            async def call(tool, arguments=None):
                started = time.perf_counter()
                response = await session.call_tool(tool, arguments or {})
                elapsed = (time.perf_counter() - started) * 1000

                payload = response.structuredContent
                if payload is None:
                    text = "\n".join(
                        item.text for item in response.content
                        if item.type == "text"
                    )
                    payload = json.loads(text)

                events.append({
                    "tool": tool,
                    "arguments": arguments or {},
                    "elapsed_ms": elapsed,
                    "result": payload,
                })

                if response.isError:
                    raise RuntimeError(f"MCP error: {payload}")

                return payload, elapsed

            async def port_call(tool, port):
                return await call(tool, {"port": port, "protocol": "tcp"})

            def managed_count(result):
                if result.get("status") != "success":
                    raise RuntimeError("Firewall inspection failed")
                return sum(
                    "ina-v1-" in line
                    for family in ("ipv4", "ipv6")
                    for line in result["data"][family].splitlines()
                )

            try:
                initial, _ = await call("show_firewall_rules")
                check("Managed firewall starts empty", managed_count(initial) == 0)

                print(f"Adding {limit} temporary rules...")
                checkpoints = {1, limit}
                checkpoints.update(
                    max(1, round(limit * fraction))
                    for fraction in (0.25, 0.50, 0.75)
                )

                for index in range(limit):
                    port = 10000 + index
                    attempted.add(port)
                    result, elapsed = await port_call("block_port", port)

                    if not (
                        result.get("status") == "success"
                        and result.get("execution_result") == "success"
                        and result.get("validation_result") == "pass"
                    ):
                        raise RuntimeError(
                            f"Rule {index + 1} failed: {result.get('message')}"
                        )

                    measurements.append({
                        "managed_rules_after_add": index + 1,
                        "request_ms": round(elapsed, 3),
                    })

                    if index + 1 in checkpoints:
                        print(f"  {index + 1}/{limit} rules installed")

                full, _ = await call("show_firewall_rules")
                check("Configured capacity reached", managed_count(full) == limit)

                extra_port = 10000 + limit
                attempted.add(extra_port)
                rejected, _ = await port_call("block_port", extra_port)

                check(
                    "One rule beyond capacity is rejected",
                    rejected.get("status") == "rejected"
                    and rejected.get("policy_result") == "denied"
                    and rejected.get("execution_result") == "not_run",
                )
                check(
                    "Capacity rejection executes no insertion",
                    all(
                        "-I" not in item["command"]
                        for item in rejected.get("commands", [])
                    ),
                )

                unchanged, _ = await call("show_firewall_rules")
                check(
                    "Rejected addition leaves rule count unchanged",
                    managed_count(unchanged) == limit,
                )

                removed, _ = await port_call("allow_port", 10000)
                check(
                    "Removal is permitted at full capacity",
                    removed.get("status") == "success"
                    and removed.get("validation_result") == "pass",
                )

                accepted, _ = await port_call("block_port", extra_port)
                check(
                    "Freed capacity permits another rule",
                    accepted.get("status") == "success"
                    and accepted.get("execution_result") == "success",
                )

                restored, _ = await call("show_firewall_rules")
                check(
                    "Rule count returns to the configured limit",
                    managed_count(restored) == limit,
                )

            except Exception as exc:
                failures.append(str(exc))

            finally:
                print("Removing temporary rules...")
                for port in sorted(attempted):
                    try:
                        result, _ = await port_call("allow_port", port)
                        if result.get("status") != "success":
                            failures.append(f"Cleanup failed for TCP {port}")
                    except Exception as exc:
                        failures.append(f"Cleanup TCP {port}: {exc}")

                try:
                    final, _ = await call("show_firewall_rules")
                    check(
                        "Cleanup leaves no managed firewall rules",
                        managed_count(final) == 0,
                    )
                except Exception as exc:
                    failures.append(str(exc))

    report = {
        "status": "FAIL" if failures else "PASS",
        "configured_max_rules": limit,
        "checks": checks,
        "measurements": measurements,
        "failures": failures,
        "measurement_note": (
            "One timing sample per occupancy level; these are exploratory "
            "measurements, not a statistically established scaling result."
        ),
    }

    (ROOT / "docs").mkdir(exist_ok=True)
    (ROOT / "logs").mkdir(exist_ok=True)

    (ROOT / "docs/capacity-results.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    (ROOT / "logs/capacity-client-events.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events)
    )

    lines = [
        "# Firewall capacity results",
        "",
        f"Overall: **{report['status']}**",
        f"Configured limit: **{limit} managed rules**",
        "",
        "| Check | Result |",
        "|---|---|",
    ]
    lines.extend(
        f"| {item['name']} | {'PASS' if item['passed'] else 'FAIL'} |"
        for item in checks
    )
    lines.extend(["", report["measurement_note"]])
    if failures:
        lines.extend(["", "Failures:"])
        lines.extend("- " + item for item in failures)

    (ROOT / "docs/capacity-results.md").write_text("\n".join(lines) + "\n")

    print("\n".join(lines))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
