"""Core orchestration: run a set of Sigma rules against a stream of Sysmon
events and collect the resulting alerts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .evaluator import EvaluationError, rule_matches
from .field_map import CATEGORY_TO_EVENT_IDS, get_event_id, get_field
from .sigma_rule import SigmaRule

LEVEL_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Alert:
    rule_title: str
    rule_id: str
    level: str
    mitre_ids: tuple
    event_index: int
    event_id: int | None
    timestamp: str | None
    matched_fields: dict
    event: dict


@dataclass
class RuleError:
    rule_title: str
    event_index: int
    message: str


def _rule_applies_to_event(rule: SigmaRule, event_id: int | None) -> bool:
    """Skip evaluating a rule against an event whose EventID cannot possibly
    match the rule's logsource category (cheap pre-filter; also avoids
    nonsensical cross-category false matches on coincidentally-named
    fields)."""
    category = rule.logsource.get("category")
    if category is None or event_id is None:
        return True  # can't rule it out; let the evaluator decide
    expected_ids = CATEGORY_TO_EVENT_IDS.get(category)
    if expected_ids is None:
        return True  # unknown category to us; don't block on it
    return event_id in expected_ids


def _extract_matched_fields(event: dict) -> dict:
    """Pull out a handful of human-readable fields for the alert summary,
    whichever of them are present on this event."""
    interesting = [
        "Image", "CommandLine", "ParentImage", "ParentCommandLine", "User",
        "TargetFilename", "TargetObject", "DestinationIp", "DestinationPort",
        "SourceImage", "TargetImage",
    ]
    out = {}
    for name in interesting:
        value = get_field(event, name)
        if value is not None:
            out[name] = value
    return out


def triage_events(
    rules: Iterable[SigmaRule], events: Iterable[dict]
) -> tuple[list[Alert], list[RuleError]]:
    """Evaluate every rule against every event. Returns (alerts, errors):
    errors capture rules whose condition this evaluator could not handle
    against a given event, without aborting the whole run."""
    rules = list(rules)
    alerts: list[Alert] = []
    errors: list[RuleError] = []

    for event_index, event in enumerate(events):
        event_id = get_event_id(event)
        timestamp = get_field(event, "UtcTime")
        for rule in rules:
            if not _rule_applies_to_event(rule, event_id):
                continue
            try:
                if rule_matches(rule, event):
                    alerts.append(
                        Alert(
                            rule_title=rule.title,
                            rule_id=rule.id,
                            level=rule.level,
                            mitre_ids=rule.mitre_ids,
                            event_index=event_index,
                            event_id=event_id,
                            timestamp=timestamp,
                            matched_fields=_extract_matched_fields(event),
                            event=event,
                        )
                    )
            except EvaluationError as exc:
                errors.append(
                    RuleError(
                        rule_title=rule.title,
                        event_index=event_index,
                        message=str(exc),
                    )
                )

    return alerts, errors


def filter_by_min_level(alerts: list[Alert], min_level: str) -> list[Alert]:
    threshold = LEVEL_ORDER.get(min_level, 0)
    return [a for a in alerts if LEVEL_ORDER.get(a.level, 0) >= threshold]
