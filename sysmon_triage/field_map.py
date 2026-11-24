"""
Maps Sigma field names (as used in Sysmon-sourced Sigma rules, e.g. ``Image``,
``CommandLine``, ``TargetObject``) to the possible JSON paths those fields can
appear under in a logged event, across the handful of common ways Sysmon
events end up serialized as JSON in the real world:

- "raw": a Sysmon event converted straight from EVTX/XML to JSON, where the
  interesting fields live under an ``EventData`` object, e.g.
  ``{"System": {"EventID": 1, ...}, "EventData": {"Image": "...", ...}}``.
- "winlogbeat": the shape produced by Winlogbeat/Elastic ingestion, where
  fields live under ``winlog.event_data`` and the event ID is
  ``winlog.event_id``, e.g. ``{"winlog": {"event_id": 1, "event_data":
  {"Image": "..."}}}``.
- "flat": a pre-flattened event where Sigma field names are already top-level
  keys, e.g. ``{"EventID": 1, "Image": "...", "CommandLine": "..."}``. This is
  also what you get if you've already normalized events yourself, and it's
  the simplest to produce by hand for test fixtures.

``get_field`` tries each shape in turn and returns the first match, so a
single log file does not need to commit to one shape consistently (useful
when mixing hand-written fixtures with real exported data).
"""
from __future__ import annotations

from typing import Any, Optional

# Sigma field name -> list of dotted paths to try, in priority order.
# "{field}" is substituted with the Sigma field name itself for the two
# shapes (raw, winlogbeat) that nest all EventData fields under one object
# with the same key names Sigma uses; "flat" is handled specially since it
# has no common prefix.
_PATH_TEMPLATES = [
    "EventData.{field}",
    "winlog.event_data.{field}",
]


def _dig(event: dict, dotted_path: str) -> Optional[Any]:
    """Walk a dotted path through nested dicts; return None if any hop misses."""
    node: Any = event
    for key in dotted_path.split("."):
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def get_field(event: dict, sigma_field: str) -> Optional[Any]:
    """
    Look up a Sigma field name (e.g. "Image", "CommandLine", "TargetObject")
    in a raw event dict, trying each known Sysmon-JSON shape in turn.

    Returns None if the field is not present under any known shape.
    """
    # Flat shape: the field is a top-level key.
    if sigma_field in event:
        return event[sigma_field]

    for template in _PATH_TEMPLATES:
        path = template.format(field=sigma_field)
        value = _dig(event, path)
        if value is not None:
            return value

    return None


def get_event_id(event: dict) -> Optional[int]:
    """
    Extract the numeric Sysmon Event ID from an event, trying each known
    shape. Returns None if it cannot be determined.
    """
    for path in ("System.EventID", "winlog.event_id", "EventID"):
        value = _dig(event, path)
        if value is None and path == "EventID" and "EventID" in event:
            value = event["EventID"]
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
    return None


# Sigma `logsource.category` -> the Sysmon Event ID(s) that category
# corresponds to. Used to skip evaluating a rule against an event whose
# EventID cannot possibly match the rule's intended log source, which both
# speeds up triage and avoids nonsensical false matches (e.g. a
# process_creation rule accidentally matching a registry event that happens
# to share a field name).
CATEGORY_TO_EVENT_IDS = {
    "process_creation": {1},
    "process_access": {10},
    "file_event": {11},
    "file_create": {11},
    "network_connection": {3},
    "image_load": {7},
    "registry_event": {12, 13, 14},
    "registry_set": {13},
    "create_remote_thread": {8},
    "pipe_created": {17, 18},
    "dns_query": {22},
}
