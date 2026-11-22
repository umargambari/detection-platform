import pytest

from detectctl.engine import UnsupportedRule, rule_matches

EVENT = {
    "Image": "C:\\Windows\\System32\\cmd.exe",
    "CommandLine": "cmd.exe /c whoami /all",
    "User": "alice",
}


def rule(detection):
    return {"detection": detection}


def test_exact_match_ignores_case():
    assert rule_matches(rule({"sel": {"User": "ALICE"}, "condition": "sel"}), EVENT)


def test_field_names_ignore_case():
    assert rule_matches(rule({"sel": {"user": "alice"}, "condition": "sel"}), EVENT)


@pytest.mark.parametrize(
    "modifier,value,expected",
    [
        ("contains", "whoami", True),
        ("contains", "ipconfig", False),
        ("startswith", "cmd.exe", True),
        ("startswith", "whoami", False),
        ("endswith", "/all", True),
        ("endswith", "cmd.exe", False),
    ],
)
def test_modifiers(modifier, value, expected):
    detection = {"sel": {f"CommandLine|{modifier}": value}, "condition": "sel"}
    assert rule_matches(rule(detection), EVENT) == expected


def test_value_list_is_or():
    detection = {"sel": {"CommandLine|contains": ["nothing", "whoami"]}, "condition": "sel"}
    assert rule_matches(rule(detection), EVENT)


@pytest.mark.parametrize(
    "values,expected",
    [(["whoami", "/all"], True), (["whoami", "ipconfig"], False)],
)
def test_all_modifier_requires_every_value(values, expected):
    detection = {"sel": {"CommandLine|contains|all": values}, "condition": "sel"}
    assert rule_matches(rule(detection), EVENT) == expected


def test_multiple_fields_are_and():
    detection = {"sel": {"Image|endswith": "\\cmd.exe", "User": "bob"}, "condition": "sel"}
    assert not rule_matches(rule(detection), EVENT)


def test_list_of_maps_is_or():
    detection = {"sel": [{"User": "bob"}, {"User": "alice"}], "condition": "sel"}
    assert rule_matches(rule(detection), EVENT)


def test_missing_field_does_not_match():
    detection = {"sel": {"Nonexistent": "x"}, "condition": "sel"}
    assert not rule_matches(rule(detection), EVENT)


CONDITIONS = {
    "sel_a": {"User": "alice"},
    "sel_b": {"User": "bob"},
    "filter_c": {"Image|endswith": "\\cmd.exe"},
}


@pytest.mark.parametrize(
    "condition,expected",
    [
        ("sel_a", True),
        ("sel_b", False),
        ("sel_a and sel_b", False),
        ("sel_a or sel_b", True),
        ("sel_a and not sel_b", True),
        ("not sel_a", False),
        ("(sel_a or sel_b) and filter_c", True),
        ("sel_b or (sel_a and not filter_c)", False),
        ("1 of sel_*", True),
        ("all of sel_*", False),
        ("1 of them", True),
        ("all of them", False),
    ],
)
def test_conditions(condition, expected):
    detection = {**CONDITIONS, "condition": condition}
    assert rule_matches(rule(detection), EVENT) == expected


@pytest.mark.parametrize(
    "detection",
    [
        {"sel": {"CommandLine|re": "who.*"}, "condition": "sel"},
        {"sel": {"CommandLine": "who*"}, "condition": "sel"},
        {"sel": ["whoami"], "condition": "sel"},
        {"sel": {"User": "alice"}, "condition": "missing"},
        {"sel": {"User": "alice"}, "condition": "(sel"},
        {"sel": {"User": "alice"}, "condition": "sel and"},
        {"sel": {"User": "alice"}, "condition": "sel sel"},
        {"sel": {"User": "alice"}, "condition": "1 of nothing_*"},
        {"sel": {"User": "alice"}, "condition": ["sel"]},
    ],
)
def test_unsupported_features_raise(detection):
    with pytest.raises(UnsupportedRule):
        rule_matches(rule(detection), EVENT)


def test_rule_without_detection_raises():
    with pytest.raises(UnsupportedRule):
        rule_matches({}, EVENT)
