"""Local stdio MCP server exposing constrained network tools."""

import argparse

from mcp.server.fastmcp import FastMCP
from pydantic import StrictFloat, StrictInt, StrictStr

from src.tools.bandwidth import BandwidthService
from src.tools.firewall import FirewallService
from src.tools.inspection import InspectionService
from src.tools.monitoring import MonitoringService


def build_server(mode="dry-run"):
    mcp = FastMCP("Intelligent Network Configuration Assistant")

    firewall = FirewallService(mode=mode)
    bandwidth = BandwidthService(mode=mode)
    monitoring = MonitoringService(mode=mode)
    inspection = InspectionService(mode=mode)

    @mcp.tool()
    def block_ip(ip_address: StrictStr, direction: StrictStr = "INPUT") -> dict:
        """Block a lab host; INPUT/FORWARD match source, OUTPUT destination."""
        return firewall.block_ip(ip_address, direction)

    @mcp.tool()
    def allow_ip(ip_address: StrictStr, direction: StrictStr = "INPUT") -> dict:
        """Remove the assistant's matching IP DROP rule."""
        return firewall.allow_ip(ip_address, direction)

    @mcp.tool()
    def block_port(
        port: StrictInt,
        protocol: StrictStr,
        direction: StrictStr = "INPUT",
    ) -> dict:
        """Block an IPv4 TCP/UDP destination port subject to policy."""
        return firewall.block_port(port, protocol, direction)

    @mcp.tool()
    def allow_port(
        port: StrictInt,
        protocol: StrictStr,
        direction: StrictStr = "INPUT",
    ) -> dict:
        """Remove the assistant's matching IPv4 port DROP rule."""
        return firewall.allow_port(port, protocol, direction)

    @mcp.tool()
    def limit_bandwidth(
        ip_address: StrictStr, rate_mbps: StrictInt | StrictFloat
    ) -> dict:
        """Limit admin's outgoing traffic to one permitted lab host."""
        return bandwidth.limit_bandwidth(ip_address, rate_mbps)

    @mcp.tool()
    def remove_bandwidth_limit(ip_address: StrictStr) -> dict:
        """Remove only the selected host's managed bandwidth limit."""
        return bandwidth.remove_bandwidth_limit(ip_address)

    @mcp.tool()
    def ping_host(ip_address: StrictStr) -> dict:
        """Send three bounded ping probes to a permitted lab address."""
        return monitoring.ping_host(ip_address)

    @mcp.tool()
    def validate_bandwidth(
        ip_address: StrictStr, duration_seconds: StrictInt = 10
    ) -> dict:
        """Measure admin-to-host TCP throughput using an iperf3 server on 5201."""
        return monitoring.validate_bandwidth(ip_address, duration_seconds)

    @mcp.tool()
    def show_firewall_rules() -> dict:
        """Inspect IPv4 and IPv6 firewall rules inside admin."""
        return inspection.show_firewall_rules()

    @mcp.tool()
    def show_bandwidth_rules() -> dict:
        """Inspect scheduler, classes, and filters on the configured interface."""
        return inspection.show_bandwidth_rules()

    return mcp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("dry-run", "live"), default="dry-run")
    args = parser.parse_args()
    build_server(args.mode).run(transport="stdio")


if __name__ == "__main__":
    main()
