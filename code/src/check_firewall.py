"""Demonstrate firewall policy and dry-run behavior."""

import json

from src.tools.firewall import FirewallService


def main():
    firewall = FirewallService(mode="dry-run")

    results = [
        firewall.block_port(23, "tcp"),
        firewall.block_port(22, "tcp"),
        firewall.block_ip("999.1.2.3"),
    ]

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
