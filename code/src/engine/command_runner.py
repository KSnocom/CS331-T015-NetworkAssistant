"""The only Python module permitted to launch network subprocesses."""

import subprocess
import time
from datetime import datetime, timezone

from src.engine.command_builder import Command


ALLOWED_EXECUTABLES = frozenset({
    "/usr/sbin/iptables",
    "/usr/sbin/ip6tables",
    "/usr/sbin/tc",
    "/usr/bin/ping",
    "/usr/bin/iperf3",
})


class CommandRunner:
    def __init__(self, mode: str = "dry-run"):
        if mode not in {"dry-run", "live"}:
            raise ValueError("Mode must be dry-run or live")
        self.mode = mode

    def run(self, command: Command) -> dict:
        if not isinstance(command, Command):
            raise TypeError("Expected a Command from the command builder")

        argv = command.argv

        if (
            not isinstance(argv, tuple)
            or not argv
            or any(
                not isinstance(arg, str) or not arg or "\x00" in arg
                for arg in argv
            )
        ):
            raise ValueError("Command must contain nonempty string arguments")

        if argv[0] not in ALLOWED_EXECUTABLES:
            raise ValueError("Executable is not permitted")

        if (
            type(command.timeout_seconds) is not int
            or not 1 <= command.timeout_seconds <= 60
        ):
            raise ValueError("Timeout must be an integer from 1 to 60 seconds")

        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": self.mode,
            "command": list(argv),
            "status": "dry-run",
            "executed": False,
            "return_code": None,
            "stdout": "",
            "stderr": "",
            "duration_seconds": 0.0,
        }

        if self.mode == "dry-run":
            return result

        started = time.monotonic()

        try:
            completed = subprocess.run(
                list(argv),
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=command.timeout_seconds,
                check=False,
                cwd="/",
                env={
                    "PATH": "/usr/sbin:/usr/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                },
            )

            result.update(
                executed=True,
                status="success" if completed.returncode == 0 else "failed",
                return_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
            )

        except subprocess.TimeoutExpired as exc:
            def as_text(value):
                if isinstance(value, bytes):
                    return value.decode("utf-8", errors="replace")
                return value or ""

            result.update(
                executed=True,
                status="timeout",
                stdout=as_text(exc.stdout),
                stderr=as_text(exc.stderr),
                error=f"Command exceeded {command.timeout_seconds} seconds",
            )

        except OSError as exc:
            result.update(
                status="error",
                error=str(exc),
            )

        result["duration_seconds"] = round(
            time.monotonic() - started, 6
        )
        return result
