"""
Evaluates a Sigma rule's detection logic directly against a single log event
dict, returning True/False rather than compiling to a static rule config.

This supports the same subset of Sigma's condition grammar as the companion
sigma2wazuh project (single identifier; "A and B [and C...]" / "A or B [or
C...]" with optional per-term "not"; "1 of them"/"all of them"; "1 of sel_*"/
"all of sel_*"; mixed and/or without parentheses is rejected), plus field
modifiers |contains, |startswith, |endswith, |re, |all.

One meaningful difference from sigma2wazuh: because this evaluator computes
a plain boolean for any selection and then negates it directly, `not` is
supported on multi-field selections too (sigma2wazuh has to reject that
case, since compiling a negated multi-field AND into static Wazuh rule XML
is not straightforward — that limitation is specific to *compiling* a
condition into config, not to evaluating one).
"""
from __future__ import annotations

import re
from typing import Any

from .field_map import get_field
from .sigma_rule import SigmaRule


class EvaluationError(Exception):
    """Raised when a rule's condition uses a construct this evaluator
    does not support."""


_SUPPORTED_MODIFIERS = {None, "contains", "startswith", "endswith", "re"}


def _match_fn(modifier: str | None):
    if modifier is None:
        return lambda actual, pattern: str(actual).lower() == str(pattern).lower()
    if modifier == "contains":
        return lambda actual, pattern: str(pattern).lower() in str(actual).lower()
    if modifier == "startswith":
        return lambda actual, pattern: str(actual).lower().startswith(str(pattern).lower())
    if modifier == "endswith":
        return lambda actual, pattern: str(actual).lower().endswith(str(pattern).lower())
    if modifier == "re":
        return lambda actual, pattern: re.search(pattern, str(actual)) is not None
    raise EvaluationError(f"Unsupported field modifier: |{modifier}")


def _field_matches(event: dict, field_key: str, pattern_or_list: Any) -> bool:
    """Evaluate one ``field|modifiers: pattern(s)`` entry against an event."""
    parts = field_key.split("|")
    field_name = parts[0]
    modifiers = parts[1:]

    all_mode = "all" in modifiers
    modifiers = [m for m in modifiers if m != "all"]
    if len(modifiers) > 1:
        raise EvaluationError(f"Unsupported combined modifiers on field: '{field_key}'")
    modifier = modifiers[0] if modifiers else None
    if modifier not in _SUPPORTED_MODIFIERS:
        raise EvaluationError(f"Unsupported field modifier: '{field_key}'")

    actual = get_field(event, field_name)
    if actual is None:
        return False
    actual_values = actual if isinstance(actual, list) else [actual]
    patterns = pattern_or_list if isinstance(pattern_or_list, list) else [pattern_or_list]
    match = _match_fn(modifier)

    def pattern_matches_any_actual(pattern) -> bool:
        return any(match(a, pattern) for a in actual_values)

    if all_mode:
        return all(pattern_matches_any_actual(p) for p in patterns)
    return any(pattern_matches_any_actual(p) for p in patterns)


def _eval_block_dict(block: dict, event: dict) -> bool:
    """A dict selection block: AND across all its field entries."""
    return all(_field_matches(event, key, val) for key, val in block.items())


def _eval_selection_value(value: Any, event: dict) -> bool:
    """A selection's value: a dict (AND of fields) or a list of dicts
    (OR of AND-groups, the list-style selection form)."""
    if isinstance(value, dict):
        return _eval_block_dict(value, event)
    if isinstance(value, list):
        return any(
            _eval_block_dict(item, event) if isinstance(item, dict) else False
            for item in value
        )
    raise EvaluationError(f"Selection value must be a dict or list of dicts, got: {value!r}")


def _wildcard_to_regex(pattern: str) -> re.Pattern:
    return re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")


def evaluate_condition(condition: str, detection: dict, event: dict) -> bool:
    """Evaluate a Sigma ``condition`` string against one log event."""
    condition = condition.strip()
    identifiers = {k: v for k, v in detection.items() if k not in ("condition", "timeframe")}

    # "1 of them" / "all of them"
    m = re.match(r"^(1|all)\s+of\s+them$", condition)
    if m:
        results = [_eval_selection_value(v, event) for v in identifiers.values()]
        return any(results) if m.group(1) == "1" else all(results)

    # "1 of sel_*" / "all of sel_*" / "1 of selection_name"
    m = re.match(r"^(1|all)\s+of\s+(\S+)$", condition)
    if m:
        pattern = m.group(2)
        if "*" in pattern:
            regex = _wildcard_to_regex(pattern)
            matched_keys = [k for k in identifiers if regex.match(k)]
        else:
            matched_keys = [pattern] if pattern in identifiers else []
        if not matched_keys:
            raise EvaluationError(
                f"No selections match pattern '{pattern}' in condition '{condition}'"
            )
        results = [_eval_selection_value(identifiers[k], event) for k in matched_keys]
        return any(results) if m.group(1) == "1" else all(results)

    # Standalone negation: "not selection"
    if condition.startswith("not "):
        remainder = condition[4:].strip()
        if remainder not in identifiers:
            raise EvaluationError(f"Unknown selection identifier '{remainder}'")
        return not _eval_selection_value(identifiers[remainder], event)

    # Single identifier
    if condition in identifiers:
        return _eval_selection_value(identifiers[condition], event)

    # "A and B [and C...]" / "A or B [or C...]", each term optionally "not "
    has_and = re.search(r"\band\b", condition) is not None
    has_or = re.search(r"\bor\b", condition) is not None
    if has_and and has_or:
        raise EvaluationError(
            f"Mixed 'and'/'or' without parentheses is not supported: '{condition}'"
        )

    if has_and or has_or:
        op = "and" if has_and else "or"
        terms = [t.strip() for t in re.split(r"\s+(?:and|or)\s+", condition)]
        term_results = []
        for term in terms:
            negate = False
            if term.startswith("not "):
                negate = True
                term = term[4:].strip()
            if term not in identifiers:
                raise EvaluationError(
                    f"Unknown selection identifier '{term}' in condition '{condition}'"
                )
            result = _eval_selection_value(identifiers[term], event)
            term_results.append(not result if negate else result)
        return all(term_results) if op == "and" else any(term_results)

    raise EvaluationError(f"Unable to parse condition: '{condition}'")


def rule_matches(rule: SigmaRule, event: dict) -> bool:
    """Return True if ``rule``'s detection logic matches ``event``."""
    return evaluate_condition(rule.condition, rule.detection, event)
