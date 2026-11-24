from sysmon_triage.field_map import get_event_id, get_field


def test_get_field_raw_shape():
    event = {"System": {"EventID": 1}, "EventData": {"Image": "cmd.exe"}}
    assert get_field(event, "Image") == "cmd.exe"


def test_get_field_winlogbeat_shape():
    event = {"winlog": {"event_id": 1, "event_data": {"Image": "cmd.exe"}}}
    assert get_field(event, "Image") == "cmd.exe"


def test_get_field_flat_shape():
    event = {"EventID": 1, "Image": "cmd.exe"}
    assert get_field(event, "Image") == "cmd.exe"


def test_get_field_missing_returns_none():
    event = {"System": {"EventID": 1}, "EventData": {"Image": "cmd.exe"}}
    assert get_field(event, "CommandLine") is None


def test_get_event_id_raw_shape():
    event = {"System": {"EventID": 1}}
    assert get_event_id(event) == 1


def test_get_event_id_winlogbeat_shape():
    event = {"winlog": {"event_id": 10}}
    assert get_event_id(event) == 10


def test_get_event_id_flat_shape():
    event = {"EventID": 11}
    assert get_event_id(event) == 11


def test_get_event_id_missing_returns_none():
    assert get_event_id({"EventData": {"Image": "cmd.exe"}}) is None
