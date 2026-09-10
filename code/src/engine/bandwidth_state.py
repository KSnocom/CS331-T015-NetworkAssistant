"""Locked, atomic storage for bandwidth ownership and host assignments."""

import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

from src.engine.validators import validate_ip, validate_bandwidth


class StateError(ValueError):
    """Stored bandwidth state is invalid; do not modify the network."""


def _validate(data):
    required = {"version", "context", "root_owned", "hosts"}

    if not isinstance(data, dict) or set(data) != required:
        raise StateError("Unexpected bandwidth state structure")

    if type(data["version"]) is not int or data["version"] != 1:
        raise StateError("Unsupported bandwidth state version")

    if data["context"] is not None and (
        not isinstance(data["context"], str) or not data["context"]
    ):
        raise StateError("Invalid network context")

    if type(data["root_owned"]) is not bool:
        raise StateError("Invalid root ownership flag")

    if not isinstance(data["hosts"], dict):
        raise StateError("Invalid host assignments")

    assigned = set()

    for ip, record in data["hosts"].items():
        try:
            if validate_ip(ip) != ip:
                raise StateError("Host addresses must be canonical")

            if not isinstance(record, dict) or set(record) != {
                "class_id", "rate_mbps", "phase"
            }:
                raise StateError("Invalid host record")

            class_id = record["class_id"]

            if type(class_id) is not int or not 1 <= class_id <= 65534:
                raise StateError("Invalid class ID")

            if class_id in assigned:
                raise StateError("Duplicate class ID")

            assigned.add(class_id)
            validate_bandwidth(record["rate_mbps"])

            if record["phase"] not in {"pending", "active", "removing"}:
                raise StateError("Invalid operation phase")

        except (TypeError, ValueError) as exc:
            raise StateError(f"Invalid host state: {exc}") from exc


class StateTransaction:
    def __init__(self, path, data):
        self.path = path
        self.data = data

    def reserve_host(self, ip_address, rate_mbps):
        """Call only after policy approval. Existing hosts keep their ID."""
        ip = validate_ip(ip_address)
        rate = validate_bandwidth(rate_mbps)
        hosts = self.data["hosts"]

        if ip in hosts:
            class_id = hosts[ip]["class_id"]
        else:
            used = {item["class_id"] for item in hosts.values()}
            class_id = next(
                (candidate for candidate in range(1, 65535)
                 if candidate not in used),
                None,
            )
            if class_id is None:
                raise StateError("No bandwidth class IDs available")

        hosts[ip] = {
            "class_id": class_id,
            "rate_mbps": rate,
            "phase": "pending",
        }
        return class_id

    def save(self):
        """Validate, write a complete temporary file, then atomically replace."""
        _validate(self.data)
        payload = json.dumps(self.data, indent=2, allow_nan=False) + "\n"

        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=".bandwidth-",
                delete=False,
            ) as stream:
                temporary_path = Path(stream.name)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())

            os.replace(temporary_path, self.path)

            directory_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)


class BandwidthState:
    def __init__(self, path=None):
        self.path = (
            Path(path)
            if path is not None
            else Path(__file__).resolve().parents[2]
            / "logs" / "bandwidth-state.json"
        )

    @contextmanager
    def locked(self):
        """Keep this lock held across read, network changes, and state writes."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_suffix(".lock")

        with lock_path.open("a", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                if self.path.exists():
                    try:
                        data = json.loads(self.path.read_text(encoding="utf-8"))
                    except (UnicodeError, ValueError) as exc:
                        raise StateError("Cannot read bandwidth state") from exc
                    _validate(data)
                else:
                    data = {
                        "version": 1,
                        "context": None,
                        "root_owned": False,
                        "hosts": {},
                    }

                # Changes persist only when the caller explicitly saves.
                yield StateTransaction(self.path, data)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
