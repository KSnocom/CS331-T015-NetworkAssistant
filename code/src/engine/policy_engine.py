"""YAML policy checks. No command execution belongs in this module."""

import ipaddress
from pathlib import Path

import yaml

from src.engine.validators import (
    validate_ip,
    validate_cidr,
    validate_port,
    validate_protocol,
    validate_port_protocol,
    validate_bandwidth,
    validate_interface,
    validate_direction,
)


class PolicyDenied(ValueError):
    """Input is valid, but the policy forbids the requested operation."""


class PolicyEngine:
    def __init__(self, policy_dir=None):
        root = (
            Path(policy_dir)
            if policy_dir is not None
            else Path(__file__).resolve().parents[2] / "policies"
        )

        self.firewall = self._load(root / "firewall.yaml", "firewall")
        self.bandwidth = self._load(root / "bandwidth.yaml", "bandwidth")

        f = self.firewall
        b = self.bandwidth

        self.protocols = self._validated_list(
            f, "allowed_protocols", validate_protocol
        )
        self.directions = self._validated_list(
            f, "allowed_directions", validate_direction
        )
        self.firewall_ranges = self._networks(f, "allowed_target_ranges")
        self.forbidden_ranges = self._networks(
            f, "forbidden_source_ranges", allow_empty=True
        )
        self.firewall_hosts = self._validated_list(
            f, "protected_hosts", validate_ip, allow_empty=True
        )
        self.protected_ports = self._validated_list(
            f, "protected_ports", validate_port, allow_empty=True
        )

        self.max_rules = f["max_rules"]
        if type(self.max_rules) is not int or self.max_rules < 1:
            raise ValueError("max_rules must be a positive integer")

        # This demo requires post-execution validation for every mutation.
        if f["require_validation"] is not True:
            raise ValueError("require_validation must be true")

        self.bandwidth_ranges = self._networks(b, "allowed_target_ranges")
        self.bandwidth_hosts = self._validated_list(
            b, "protected_hosts", validate_ip, allow_empty=True
        )
        self.interface = validate_interface(b["interface"])
        self.minimum_mbps = validate_bandwidth(b["minimum_mbps"])
        self.maximum_mbps = validate_bandwidth(b["maximum_mbps"])
        self.default_mbps = validate_bandwidth(b["default_mbps"])

        if not (
            self.minimum_mbps
            <= self.default_mbps
            <= self.maximum_mbps
        ):
            raise ValueError(
                "Bandwidth policy must satisfy minimum <= default <= maximum"
            )

    @staticmethod
    def _load(path, section):
        with path.open(encoding="utf-8") as stream:
            data = yaml.safe_load(stream)

        if not isinstance(data, dict) or not isinstance(
            data.get(section), dict
        ):
            raise ValueError(f"Missing policy mapping: {section}")

        return data[section]

    @staticmethod
    def _validated_list(data, key, validator, allow_empty=False):
        values = data[key]
        if not isinstance(values, list) or (not values and not allow_empty):
            raise ValueError(f"{key} must be a valid YAML list")
        return {validator(value) for value in values}

    @classmethod
    def _networks(cls, data, key, allow_empty=False):
        values = cls._validated_list(
            data, key, validate_cidr, allow_empty=allow_empty
        )
        return tuple(ipaddress.ip_network(value) for value in values)

    @staticmethod
    def _in_ranges(address, ranges):
        return any(
            address.version == network.version and address in network
            for network in ranges
        )

    def check_target(self, ip_address):
        """Read-only monitoring targets must also remain inside the lab."""
        ip = validate_ip(ip_address)
        if not self._in_ranges(
            ipaddress.ip_address(ip), self.firewall_ranges
        ):
            raise PolicyDenied("Target is outside the allowed lab ranges")
        return ip

    def _check_direction(self, direction):
        direction = validate_direction(direction)
        if direction not in self.directions:
            raise PolicyDenied("Traffic direction is not permitted")
        return direction

    def check_ip(self, ip_address, direction="INPUT"):
        """Authorize an IP firewall change, including removal."""
        ip = self.check_target(ip_address)
        direction = self._check_direction(direction)
        address = ipaddress.ip_address(ip)

        if ip in self.firewall_hosts:
            raise PolicyDenied("Firewall changes to this host are protected")

        if self._in_ranges(address, self.forbidden_ranges):
            raise PolicyDenied("Address belongs to a forbidden range")

        return {"ip_address": ip, "direction": direction}

    def check_port(self, port, protocol, direction="INPUT"):
        """Authorize a TCP/UDP port firewall change."""
        port = validate_port(port)
        protocol = validate_port_protocol(protocol)
        direction = self._check_direction(direction)

        if protocol not in self.protocols:
            raise PolicyDenied("Protocol is not permitted")

        if port in self.protected_ports:
            raise PolicyDenied(f"Port {port} is protected")

        return {
            "port": port,
            "protocol": protocol,
            "direction": direction,
        }

    def check_rule_capacity(self, current_rules):
        """Call before adding a new managed rule, never before removal."""
        if type(current_rules) is not int or current_rules < 0:
            raise ValueError("Rule count must be a nonnegative integer")

        if current_rules >= self.max_rules:
            raise PolicyDenied("Maximum managed firewall rule count reached")

    def check_bandwidth(self, ip_address, rate_mbps=None):
        """None means authorize removal of an existing bandwidth limit."""
        ip = validate_ip(ip_address)
        address = ipaddress.ip_address(ip)

        if not self._in_ranges(address, self.bandwidth_ranges):
            raise PolicyDenied("Target is outside the allowed lab ranges")

        if ip in self.bandwidth_hosts:
            raise PolicyDenied("Bandwidth changes to this host are protected")

        result = {"ip_address": ip, "interface": self.interface}

        if rate_mbps is not None:
            rate = validate_bandwidth(rate_mbps)

            if not self.minimum_mbps <= rate <= self.maximum_mbps:
                raise PolicyDenied(
                    f"Bandwidth must be between {self.minimum_mbps:g} "
                    f"and {self.maximum_mbps:g} Mbps"
                )

            result["rate_mbps"] = rate

        return result
