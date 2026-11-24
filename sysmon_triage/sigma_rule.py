"""
Minimal Sigma rule loader: parses a Sigma YAML rule file into a structured
``SigmaRule`` object. This covers the subset of the Sigma spec needed to
drive detection against Sysmon-sourced logs (title, id, logsource, detection
block, level, tags); it does not implement the full Sigma spec (no
correlation rules, no field-mapping pipelines).

This mirrors the parser used in the companion sigma2wazuh project (same
author, same methodology) so that the same Sigma rule files can drive both
a static Wazuh-config generator and this live log-triage engine.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import yaml


class SigmaParseError(Exception):
    """Raised when a Sigma rule file cannot be parsed into a usable rule."""


_MITRE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


@dataclass(frozen=True)
class SigmaRule:
    title: str
    id: str
    description: str
    level: str
    logsource: dict
    detection: dict
    tags: tuple = field(default_factory=tuple)
    falsepositives: tuple = field(default_factory=tuple)
    raw: dict = field(default_factory=dict)

    @property
    def mitre_ids(self) -> tuple:
        """MITRE ATT&CK technique IDs extracted from this rule's tags."""
        ids = []
        for tag in self.tags:
            m = _MITRE_TAG_RE.match(tag)
            if m:
                ids.append(m.group(1).upper())
        return tuple(ids)

    @property
    def condition(self) -> str:
        return self.detection.get("condition", "")


def _require(data: dict, key: str, rule_path: str) -> Any:
    if key not in data:
        raise SigmaParseError(f"{rule_path}: missing required field '{key}'")
    return data[key]


def load_sigma_rule(path: str | Path) -> SigmaRule:
    """Load and parse a single Sigma YAML rule file."""
    path = Path(path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise SigmaParseError(f"{path}: invalid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise SigmaParseError(f"{path}: rule is not a YAML mapping")

    title = _require(data, "title", str(path))
    rule_id = data.get("id", title)
    detection = _require(data, "detection", str(path))
    if "condition" not in detection:
        raise SigmaParseError(f"{path}: detection block missing 'condition'")
    logsource = _require(data, "logsource", str(path))

    return SigmaRule(
        title=title,
        id=rule_id,
        description=data.get("description", ""),
        level=data.get("level", "medium"),
        logsource=logsource,
        detection=detection,
        tags=tuple(data.get("tags", [])),
        falsepositives=tuple(data.get("falsepositives", [])),
        raw=data,
    )


def load_sigma_rules_from_dir(dir_path: str | Path) -> Iterator[SigmaRule]:
    """Load every ``*.yml``/``*.yaml`` file in a directory as a SigmaRule."""
    dir_path = Path(dir_path)
    for path in sorted(dir_path.glob("*.yml")) + sorted(dir_path.glob("*.yaml")):
        yield load_sigma_rule(path)
