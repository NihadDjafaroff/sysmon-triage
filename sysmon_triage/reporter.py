"""Formats triage results for human (text) or machine (JSON) consumption."""
from __future__ import annotations

import json

from .triage import Alert, RuleError

_LEVEL_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "informational": "⚪",
}


def format_text(alerts: list[Alert], errors: list[RuleError], total_events: int) -> str:
    lines = []
    lines.append(f"Scanned {total_events} event(s); {len(alerts)} alert(s) raised.")
    lines.append("")

    if not alerts:
        lines.append("No matches.")
    for alert in alerts:
        icon = _LEVEL_ICON.get(alert.level, "•")
        mitre = f" [{', '.join(alert.mitre_ids)}]" if alert.mitre_ids else ""
        lines.append(
            f"{icon} [{alert.level.upper()}] {alert.rule_title}{mitre} "
            f"— event #{alert.event_index} (EventID {alert.event_id}, {alert.timestamp})"
        )
        for field_name, value in alert.matched_fields.items():
            lines.append(f"      {field_name}: {value}")
        lines.append("")

    if errors:
        lines.append(f"{len(errors)} rule evaluation error(s):")
        for err in errors:
            lines.append(f"  - {err.rule_title} @ event #{err.event_index}: {err.message}")

    return "\n".join(lines)


def format_json(alerts: list[Alert], errors: list[RuleError], total_events: int) -> str:
    payload = {
        "total_events": total_events,
        "alert_count": len(alerts),
        "alerts": [
            {
                "rule_title": a.rule_title,
                "rule_id": a.rule_id,
                "level": a.level,
                "mitre_ids": list(a.mitre_ids),
                "event_index": a.event_index,
                "event_id": a.event_id,
                "timestamp": a.timestamp,
                "matched_fields": a.matched_fields,
            }
            for a in alerts
        ],
        "errors": [
            {
                "rule_title": e.rule_title,
                "event_index": e.event_index,
                "message": e.message,
            }
            for e in errors
        ],
    }
    return json.dumps(payload, indent=2, default=str)
