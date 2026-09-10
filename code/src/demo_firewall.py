"""Run through Docker Compose inside the admin container."""

import json

from src.tools.firewall import FirewallService


def check(step, result, expected_status="success", expected_execution=None):
    print(json.dumps({"step": step, **result}), flush=True)

    if result["status"] != expected_status:
        raise RuntimeError(
            f"{step}: expected {expected_status}, got {result['status']}"
        )

    if (
        expected_execution is not None
        and result["execution_result"] != expected_execution
    ):
        raise RuntimeError(
            f"{step}: unexpected execution result "
            f"{result['execution_result']}"
        )

    if expected_status == "success" and result["validation_result"] != "pass":
        raise RuntimeError(f"{step}: rule verification did not pass")


def main():
    firewall = FirewallService(mode="live")

    try:
        check("block_port_23", firewall.block_port(23, "tcp"))

        check(
            "repeat_block_without_duplicate",
            firewall.block_port(23, "tcp"),
            expected_execution="no_change",
        )

        check(
            "reject_protected_port",
            firewall.block_port(22, "tcp"),
            expected_status="rejected",
        )

        check(
            "reject_protected_host",
            firewall.block_ip("172.30.50.10"),
            expected_status="rejected",
        )

        check(
            "reject_invalid_ip",
            firewall.block_ip("999.1.2.3"),
            expected_status="invalid",
        )

    finally:
        # Attempt cleanup even when an earlier demonstration step fails.
        check("remove_port_23_block", firewall.allow_port(23, "tcp"))

    check(
        "repeat_allow_without_change",
        firewall.allow_port(23, "tcp"),
        expected_execution="no_change",
    )


if __name__ == "__main__":
    main()
