"""Append-only run ledger shared by the ART and Wazuh agents."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class RunLedger:
    """Small JSONL ledger for correlating atomic runs with Wazuh alerts."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        """Append one run record and return the persisted row."""

        persisted = dict(record)
        persisted.setdefault("run_id", str(uuid.uuid4()))
        persisted.setdefault("recorded_utc", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(persisted, sort_keys=True) + "\n")
        return persisted

    def read_all(self, limit: int = 100) -> list[dict[str, Any]]:
        """Read the most recent JSONL records."""

        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        rows: list[dict[str, Any]] = []
        for line in lines[-limit:]:
            if line.strip():
                rows.append(json.loads(line))
        return rows
