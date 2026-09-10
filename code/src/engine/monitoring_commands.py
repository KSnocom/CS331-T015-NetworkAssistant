"""Fixed monitoring commands with bounded execution times."""

from src.engine.command_builder import Command
from src.engine.validators import ValidationError, validate_ip


def ping_command(ip_address):
    ip = validate_ip(ip_address)
    return Command((
        "/usr/bin/ping",
        "-n", "-c", "3", "-W", "2", "-w", "8", ip,
    ), timeout_seconds=10)


def iperf_command(ip_address, duration_seconds=10):
    ip = validate_ip(ip_address)

    if type(duration_seconds) is not int or not 1 <= duration_seconds <= 30:
        raise ValidationError("Duration must be an integer from 1 to 30 seconds")

    return Command((
        "/usr/bin/iperf3",
        "-c", ip,
        "-p", "5201",
        "-t", str(duration_seconds),
        "-O", "2",
        "--connect-timeout", "2000",
        "-J",
    ), timeout_seconds=duration_seconds + 8)
