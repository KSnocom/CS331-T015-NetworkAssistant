"""Inspect firewall and bandwidth configuration."""

import json

from src.engine.command_builder import show_firewall_rules
from src.engine.bandwidth_commands import (
    show_qdiscs,
    show_classes,
    show_filters,
)
from src.tools.monitoring import MonitoringService


class InspectionService(MonitoringService):
    def show_firewall_rules(self):
        return self._read(
            "SHOW_FIREWALL_RULES",
            {},
            lambda: [show_firewall_rules(4), show_firewall_rules(6)],
            lambda outputs: {
                "ipv4": outputs[0],
                "ipv6": outputs[1],
            },
        )

    def show_bandwidth_rules(self):
        interface = self.policy.interface
        return self._read(
            "SHOW_BANDWIDTH_RULES",
            {"interface": interface},
            lambda: [
                show_qdiscs(interface),
                show_classes(interface),
                show_filters(interface),
            ],
            lambda outputs: {
                "qdiscs": json.loads(outputs[0]),
                "classes": json.loads(outputs[1]),
                "filters": json.loads(outputs[2]),
            },
        )
