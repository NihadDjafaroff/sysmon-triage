"""Reads Sysmon events from a JSON Lines (JSONL) log file: one JSON object
per line, in any of the shapes field_map.py understands (raw EventData,
Winlogbeat, or flat)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator


class LogReadError(Exception):
    """Raised when a log line cannot be parsed as JSON."""


def read_events(path: str | Path) -> Iterator[dict]:
    """Yield one dict per non-blank line of a JSONL log file.

    Blank lines are skipped. A malformed line raises LogReadError naming the
    line number, rather than silently skipping bad data — a log-triage tool
    that quietly drops unparseable events is worse than one that fails loud.
    """
    path = Path(path)
    with open(path, "r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise LogReadError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if not isinstance(event, dict):
                raise LogReadError(f"{path}:{line_no}: event is not a JSON object")
            yield event
