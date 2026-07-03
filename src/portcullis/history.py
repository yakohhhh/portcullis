"""Local score history for the interactive report.

Scanning the same stack over time is more useful when you can see the trend,
so ``portcullis report`` appends each run's score to a small JSON file (kept
entirely local, like everything else). The interactive report draws a
sparkline from it.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from portcullis.model import ScanResult

SCHEMA = 1
MAX_RUNS = 200


@dataclass
class Run:
    timestamp: str
    score: int
    grade: str
    findings: int
    services: int

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "score": self.score,
            "grade": self.grade,
            "findings": self.findings,
            "services": self.services,
        }


def load(path: Path) -> list[Run]:
    """Load the history file, returning an empty list if absent or unreadable."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    runs = data.get("runs", []) if isinstance(data, dict) else []
    result: list[Run] = []
    for entry in runs:
        if not isinstance(entry, dict):
            continue
        try:
            result.append(Run(
                timestamp=str(entry["timestamp"]),
                score=int(entry["score"]),
                grade=str(entry["grade"]),
                findings=int(entry.get("findings", 0)),
                services=int(entry.get("services", 0)),
            ))
        except (KeyError, TypeError, ValueError):
            continue
    return result


def record(path: Path, result: ScanResult, *, timestamp: str | None = None) -> list[Run]:
    """Append this scan to the history file and return the full run list."""
    runs = load(path)
    runs.append(Run(
        timestamp=timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        score=result.score,
        grade=result.grade,
        findings=len(result.findings),
        services=len(result.stack.services),
    ))
    runs = runs[-MAX_RUNS:]
    # A read-only location must not fail the report.
    with contextlib.suppress(OSError):
        path.write_text(
            json.dumps({"schema": SCHEMA, "runs": [r.to_dict() for r in runs]}, indent=2),
            encoding="utf-8",
        )
    return runs
