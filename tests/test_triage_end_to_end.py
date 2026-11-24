"""End-to-end tests: load the real example Sigma rules and sample logs
shipped in examples/, and assert the expected alerts fire (and don't)."""
from pathlib import Path

from sysmon_triage.log_reader import read_events
from sysmon_triage.sigma_rule import load_sigma_rules_from_dir
from sysmon_triage.triage import triage_events

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
RULES_DIR = EXAMPLES_DIR / "sigma_rules"
LOGS_DIR = EXAMPLES_DIR / "sample_logs"


def _run(log_filename):
    rules = list(load_sigma_rules_from_dir(RULES_DIR))
    events = list(read_events(LOGS_DIR / log_filename))
    return triage_events(rules, events)


def test_four_example_rules_load():
    rules = list(load_sigma_rules_from_dir(RULES_DIR))
    assert len(rules) == 4
    titles = {r.title for r in rules}
    assert "Suspicious PowerShell Download Command" in titles
    assert "Suspicious Access to LSASS Memory" in titles
    assert "Suspicious Persistence via Scheduled Task or Service Creation" in titles
    assert "Rundll32 Executed With Uncommon Export Function Names" in titles


def test_malicious_events_all_trigger_exactly_one_alert_each():
    alerts, errors = _run("malicious_events.jsonl")
    assert errors == []
    # 6 malicious events in the fixture, each should trigger exactly one rule
    assert len(alerts) == 6
    fired_titles = sorted(a.rule_title for a in alerts)
    assert fired_titles == sorted([
        "Suspicious PowerShell Download Command",
        "Suspicious Access to LSASS Memory",
        "Suspicious Persistence via Scheduled Task or Service Creation",
        "Suspicious Persistence via Scheduled Task or Service Creation",
        "Rundll32 Executed With Uncommon Export Function Names",
        "Rundll32 Executed With Uncommon Export Function Names",
    ])


def test_benign_events_trigger_no_alerts():
    """Crucially includes a WerFault-accessing-lsass event, which must be
    excluded by the 'and not filter' clause rather than firing a false
    positive."""
    alerts, errors = _run("benign_events.jsonl")
    assert errors == []
    assert alerts == []


def test_combined_demo_separates_signal_from_noise():
    alerts, errors = _run("combined_demo.jsonl")
    assert errors == []
    assert len(alerts) == 6

    events = list(read_events(LOGS_DIR / "combined_demo.jsonl"))
    assert len(events) == 12


def test_lsass_alert_has_critical_level_and_mitre_tag():
    alerts, _ = _run("malicious_events.jsonl")
    lsass_alerts = [a for a in alerts if a.rule_title == "Suspicious Access to LSASS Memory"]
    assert len(lsass_alerts) == 1
    assert lsass_alerts[0].level == "critical"
    assert "T1003.001" in lsass_alerts[0].mitre_ids
