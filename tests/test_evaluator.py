import pytest

from sysmon_triage.evaluator import EvaluationError, evaluate_condition


def ev(**eventdata):
    return {"System": {"EventID": 1}, "EventData": eventdata}


# --- single selection, plain equality / list-OR ---

def test_single_identifier_plain_match():
    detection = {"selection": {"Image": "cmd.exe"}, "condition": "selection"}
    assert evaluate_condition("selection", detection, ev(Image="cmd.exe")) is True
    assert evaluate_condition("selection", detection, ev(Image="powershell.exe")) is False


def test_list_value_is_or():
    detection = {
        "selection": {"CommandLine|contains": ["foo", "bar"]},
        "condition": "selection",
    }
    assert evaluate_condition("selection", detection, ev(CommandLine="has foo in it")) is True
    assert evaluate_condition("selection", detection, ev(CommandLine="has bar in it")) is True
    assert evaluate_condition("selection", detection, ev(CommandLine="has neither")) is False


# --- modifiers ---

@pytest.mark.parametrize(
    "modifier,field_value,pattern,expected",
    [
        ("contains", "C:\\temp\\evil.exe", "evil", True),
        ("contains", "C:\\temp\\good.exe", "evil", False),
        ("startswith", "C:\\Windows\\System32\\cmd.exe", "C:\\Windows", True),
        ("startswith", "C:\\temp\\cmd.exe", "C:\\Windows", False),
        ("endswith", "C:\\Windows\\System32\\cmd.exe", "\\cmd.exe", True),
        ("endswith", "C:\\Windows\\System32\\powershell.exe", "\\cmd.exe", False),
    ],
)
def test_modifiers(modifier, field_value, pattern, expected):
    detection = {"selection": {f"Image|{modifier}": pattern}, "condition": "selection"}
    assert evaluate_condition("selection", detection, ev(Image=field_value)) is expected


def test_re_modifier():
    detection = {"selection": {"Image|re": r"cmd\.exe$"}, "condition": "selection"}
    assert evaluate_condition("selection", detection, ev(Image="C:\\Windows\\cmd.exe")) is True
    assert evaluate_condition("selection", detection, ev(Image="C:\\Windows\\cmd.exe.bak")) is False


def test_all_modifier_requires_every_pattern():
    detection = {
        "selection": {"CommandLine|contains|all": ["foo", "bar"]},
        "condition": "selection",
    }
    assert evaluate_condition("selection", detection, ev(CommandLine="foo and bar")) is True
    assert evaluate_condition("selection", detection, ev(CommandLine="only foo")) is False


def test_matching_is_case_insensitive():
    detection = {"selection": {"Image|endswith": "\\CMD.EXE"}, "condition": "selection"}
    assert evaluate_condition("selection", detection, ev(Image="c:\\windows\\cmd.exe")) is True


# --- missing field never matches ---

def test_missing_field_does_not_match():
    detection = {"selection": {"CommandLine|contains": "foo"}, "condition": "selection"}
    assert evaluate_condition("selection", detection, ev(Image="cmd.exe")) is False


# --- and / or / not ---

def test_and_condition():
    detection = {
        "a": {"Image": "cmd.exe"},
        "b": {"User": "admin"},
        "condition": "a and b",
    }
    assert evaluate_condition("a and b", detection, ev(Image="cmd.exe", User="admin")) is True
    assert evaluate_condition("a and b", detection, ev(Image="cmd.exe", User="guest")) is False


def test_or_condition():
    detection = {
        "a": {"Image": "cmd.exe"},
        "b": {"Image": "powershell.exe"},
        "condition": "a or b",
    }
    assert evaluate_condition("a or b", detection, ev(Image="cmd.exe")) is True
    assert evaluate_condition("a or b", detection, ev(Image="powershell.exe")) is True
    assert evaluate_condition("a or b", detection, ev(Image="notepad.exe")) is False


def test_selection_and_not_filter():
    detection = {
        "selection": {"TargetImage": "lsass.exe"},
        "filter": {"Image": "werfault.exe"},
        "condition": "selection and not filter",
    }
    assert evaluate_condition(
        "selection and not filter", detection,
        ev(TargetImage="lsass.exe", Image="mimikatz.exe"),
    ) is True
    assert evaluate_condition(
        "selection and not filter", detection,
        ev(TargetImage="lsass.exe", Image="werfault.exe"),
    ) is False


def test_standalone_not_on_multi_field_selection_is_supported():
    """Unlike sigma2wazuh (which must reject this when compiling to Wazuh
    XML), the live evaluator can negate a multi-field selection directly."""
    detection = {
        "selection": {"Image": "cmd.exe", "User": "admin"},
        "condition": "not selection",
    }
    # Both fields match -> selection True -> "not selection" False
    assert evaluate_condition("not selection", detection, ev(Image="cmd.exe", User="admin")) is False
    # Selection doesn't match -> "not selection" True
    assert evaluate_condition("not selection", detection, ev(Image="other.exe", User="admin")) is True


def test_mixed_and_or_without_parentheses_raises():
    detection = {
        "a": {"Image": "cmd.exe"},
        "b": {"User": "admin"},
        "c": {"User": "guest"},
        "condition": "a and b or c",
    }
    with pytest.raises(EvaluationError):
        evaluate_condition("a and b or c", detection, ev(Image="cmd.exe"))


# --- "1 of" / "all of" ---

def test_of_them():
    detection = {
        "sel_a": {"Image": "cmd.exe"},
        "sel_b": {"Image": "powershell.exe"},
        "condition": "1 of them",
    }
    assert evaluate_condition("1 of them", detection, ev(Image="cmd.exe")) is True
    assert evaluate_condition("1 of them", detection, ev(Image="notepad.exe")) is False


def test_all_of_them():
    detection = {
        "sel_a": {"Image": "cmd.exe"},
        "sel_b": {"User": "admin"},
        "condition": "all of them",
    }
    assert evaluate_condition("all of them", detection, ev(Image="cmd.exe", User="admin")) is True
    assert evaluate_condition("all of them", detection, ev(Image="cmd.exe", User="guest")) is False


def test_of_wildcard_selection():
    detection = {
        "sel_a": {"Image": "cmd.exe"},
        "sel_b": {"Image": "powershell.exe"},
        "other": {"Image": "notepad.exe"},
        "condition": "1 of sel_*",
    }
    assert evaluate_condition("1 of sel_*", detection, ev(Image="cmd.exe")) is True
    assert evaluate_condition("1 of sel_*", detection, ev(Image="notepad.exe")) is False


# --- list-style (OR-of-AND) selections ---

def test_list_style_selection():
    detection = {
        "selection": [
            {"Image": "rundll32.exe", "CommandLine|contains": "JSRunAction"},
            {"Image": "rundll32.exe", "CommandLine|contains": "Control_RunDLL"},
        ],
        "condition": "selection",
    }
    assert evaluate_condition(
        "selection", detection,
        ev(Image="rundll32.exe", CommandLine="...JSRunAction()"),
    ) is True
    assert evaluate_condition(
        "selection", detection,
        ev(Image="rundll32.exe", CommandLine="something else entirely"),
    ) is False


def test_unsupported_modifier_raises():
    detection = {"selection": {"Image|fuzzy": "cmd.exe"}, "condition": "selection"}
    with pytest.raises(EvaluationError):
        evaluate_condition("selection", detection, ev(Image="cmd.exe"))


def test_unknown_identifier_raises():
    detection = {"selection": {"Image": "cmd.exe"}, "condition": "selection and ghost"}
    with pytest.raises(EvaluationError):
        evaluate_condition("selection and ghost", detection, ev(Image="cmd.exe"))
