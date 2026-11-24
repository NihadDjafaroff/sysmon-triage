# sysmon-triage

![Tests](https://img.shields.io/badge/tests-36%20passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

A small, dependency-light Python tool that applies [Sigma](https://github.com/SigmaHQ/sigma)
detection rules **directly against Sysmon-sourced log events**, rather than compiling them into
a SIEM's static rule config. Point it at a directory of Sigma rules and a JSONL log file, and it
tells you which rules fired on which events, with MITRE ATT&CK tags and severity included.

This is the companion project to [`sigma2wazuh`](../sigma2wazuh) (same author): that project
*compiles* Sigma rules into static Wazuh `local_rules.xml` config; this one *evaluates* the same
Sigma condition logic live, one event at a time. The two share the same four example Sigma rules
and the same supported subset of Sigma's condition grammar, so you can see the identical
detection logic expressed both ways.

## Why build this separately from sigma2wazuh?

Compiling to a SIEM's rule format and evaluating directly against raw logs are genuinely
different problems with different constraints:

- A compiler has to express the logic in the *target format's* grammar (Wazuh XML rule
  relationships), which is sometimes more restrictive than Sigma itself — for example,
  sigma2wazuh has to reject `not` on a multi-field selection, because there's no clean way to
  express a negated compound AND as Wazuh rule XML.
- A live evaluator just computes a boolean and can negate it directly — no such restriction
  exists here. See [`tests/test_evaluator.py::test_standalone_not_on_multi_field_selection_is_supported`](tests/test_evaluator.py)
  for a working example sigma2wazuh cannot support.

Building both made that difference concrete rather than theoretical.

## Quick demo

```bash
pip install -r requirements.txt
python3 -m sysmon_triage scan \
  --rules examples/sigma_rules \
  --logs examples/sample_logs/combined_demo.jsonl \
  --min-level medium
```

`examples/sample_logs/combined_demo.jsonl` interleaves 6 malicious Sysmon events (one for each
example Sigma rule, including the edge cases each rule is designed to handle) with 6 benign
events chosen specifically to be plausible false-positive bait — including a `WerFault.exe`
process touching `lsass.exe`, which the LSASS-access rule must *not* flag thanks to its
`and not filter` clause. The tool correctly raises exactly 6 alerts and flags none of the benign
events.

## What it handles

- Sigma `detection` blocks: single identifier; `A and B [and C...]` / `A or B [or C...]`
  (each term optionally prefixed `not`); `1 of them` / `all of them`; `1 of sel_*` / `all of
  sel_*` wildcard selection matching.
- Field modifiers: `|contains`, `|startswith`, `|endswith`, `|re`, `|all` (require every pattern
  in a list to match, rather than any).
- Both selection styles: a dict (AND across its fields) and a list of dicts (OR across
  AND-groups).
- Three common Sysmon-as-JSON shapes transparently: raw EVTX-to-JSON (`EventData.*`),
  Winlogbeat/Elastic ingestion (`winlog.event_data.*`), and flat/pre-normalized events — see
  [`sysmon_triage/field_map.py`](sysmon_triage/field_map.py).
- `logsource.category` pre-filtering against the event's actual `EventID`, so a
  `process_creation` rule is never evaluated against, say, a registry event.

## What it deliberately does not handle

(Matching sigma2wazuh's documented scope, so the same rule files work with both tools.)

- Mixed `and`/`or` in one condition without parentheses (rejected with a clear error rather than
  guessed at).
- Sigma correlation rules (multi-event/time-window conditions).
- Field-mapping pipelines beyond the three JSON shapes above.

## Project structure

```
sysmon-triage/
├── sysmon_triage/
│   ├── sigma_rule.py      — Sigma YAML rule loader
│   ├── field_map.py        — Sysmon-JSON-shape-agnostic field lookup
│   ├── evaluator.py         — condition-string evaluator (the detection engine)
│   ├── log_reader.py        — JSONL log file reader
│   ├── triage.py             — orchestration: rules × events → alerts
│   ├── reporter.py            — text/JSON output formatting
│   └── cli.py                  — `scan` subcommand
├── examples/
│   ├── sigma_rules/              — 4 original example Sigma rules (shared with sigma2wazuh)
│   └── sample_logs/
│       ├── malicious_events.jsonl  — one triggering event per rule
│       ├── benign_events.jsonl       — deliberately close-but-no-match events
│       └── combined_demo.jsonl         — interleaved, for the live demo above
└── tests/                                 — 36 tests, unit + end-to-end
```

## Usage

```bash
python3 -m sysmon_triage scan --rules <rules_dir> --logs <events.jsonl> \
    [--format text|json] [--min-level informational|low|medium|high|critical]
```

Log files are JSON Lines: one JSON object per line, in any of the three shapes above. See
`examples/sample_logs/` for real examples of each.

## Testing

```bash
pip install -r requirements.txt pytest
python3 -m pytest tests/ -v
```

36 tests covering: field-shape resolution, every supported modifier (including case-insensitive
matching and the `|all` AND-of-list behavior), `and`/`or`/`not` combinations, the
mixed-and/or-rejection error path, wildcard `1 of`/`all of` selection matching, and a full
end-to-end run against the example rules and sample logs confirming exact alert counts — malicious
events all fire, benign events (including the designed-to-be-tricky `WerFault` case) do not.

## Background

Built as a companion piece to `sigma2wazuh` to demonstrate the same Sigma detection logic
applied two different ways — compiled to static SIEM config, and evaluated live against raw
logs.

## License

[MIT](LICENSE)
