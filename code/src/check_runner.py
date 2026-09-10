"""Inspect firewall rules through the centralized command layer."""

import argparse
import json

from src.engine.command_builder import show_firewall_rules
from src.engine.command_runner import CommandRunner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=("dry-run", "live"),
        default="dry-run",
    )
    args = parser.parse_args()

    result = CommandRunner(args.mode).run(show_firewall_rules())
    print(json.dumps(result, indent=2))

    if result["status"] not in {"success", "dry-run"}:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
