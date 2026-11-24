"""Command-line interface for sysmon-triage."""
from __future__ import annotations

import argparse
import sys

from .log_reader import LogReadError, read_events
from .reporter import format_json, format_text
from .sigma_rule import SigmaParseError, load_sigma_rules_from_dir
from .triage import filter_by_min_level, triage_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sysmon-triage",
        description="Apply Sigma detection rules directly against Sysmon-sourced logs.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a log file against a directory of Sigma rules.")
    scan.add_argument("--rules", required=True, help="Directory of Sigma .yml rule files.")
    scan.add_argument("--logs", required=True, help="Path to a JSONL log file.")
    scan.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output format."
    )
    scan.add_argument(
        "--min-level",
        choices=["informational", "low", "medium", "high", "critical"],
        default="informational",
        help="Only report alerts at or above this severity.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            rules = list(load_sigma_rules_from_dir(args.rules))
        except SigmaParseError as exc:
            print(f"Error loading Sigma rules: {exc}", file=sys.stderr)
            return 1

        if not rules:
            print(f"No Sigma rule files (*.yml/*.yaml) found in '{args.rules}'", file=sys.stderr)
            return 1

        try:
            events = list(read_events(args.logs))
        except LogReadError as exc:
            print(f"Error reading logs: {exc}", file=sys.stderr)
            return 1

        alerts, errors = triage_events(rules, events)
        alerts = filter_by_min_level(alerts, args.min_level)

        if args.format == "json":
            print(format_json(alerts, errors, len(events)))
        else:
            print(format_text(alerts, errors, len(events)))

        return 0 if not errors else 2

    return 1
