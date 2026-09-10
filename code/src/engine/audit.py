"""Append structured audit events without printing to MCP stdout."""

import fcntl
import json
import os
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    def __init__(self, path=None):
        self.path = (
            Path(path)
            if path is not None
            else Path(__file__).resolve().parents[2] / "logs" / "audit.jsonl"
        )

    def write(self, event: dict) -> dict:
        required = {
            "action",
            "parameters",
            "policy_result",
            "execution_result",
            "validation_result",
        }

        if not isinstance(event, dict) or not required.issubset(event):
            raise ValueError("Audit event is missing required fields")

        record = dict(event)
        record["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Serialize before opening the file, so invalid events append nothing.
        line = json.dumps(record, ensure_ascii=True, allow_nan=False) + "\n"

        self.path.parent.mkdir(parents=True, exist_ok=True)

        with self.path.open("a", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

        return record
