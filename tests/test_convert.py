from pathlib import Path

import pytest

from detectctl.convert import TARGETS, ConversionError, convert_paths, convert_rule

RULES = Path(__file__).resolve().parent.parent / "rules"
RULE = RULES / "windows" / "proc_creation_win_powershell_encoded_command.yml"

EXPECTED_TABLE = {
    "xdr": "DeviceProcessEvents",
    "asim": "imProcessCreate",
    "azuremonitor": "SecurityEvent",
}


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_rule_converts_to_expected_table(target):
    query = convert_rule(RULE, target)
    assert query.startswith(EXPECTED_TABLE[target])
    assert "powershell.exe" in query
    assert "-enc" in query


def test_targets_do_not_contaminate_each_other():
    # Regression: converting for one target must not change the next one's output.
    first = convert_rule(RULE, "azuremonitor")
    convert_rule(RULE, "xdr")
    assert convert_rule(RULE, "azuremonitor") == first


def test_unknown_target_raises():
    with pytest.raises(ConversionError, match="unknown target"):
        convert_rule(RULE, "splunk")


def test_unparseable_rule_raises(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("title: [unclosed\n")
    with pytest.raises(ConversionError):
        convert_rule(bad, "xdr")


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_all_repo_rules_convert(target):
    results = convert_paths(RULES, target)
    assert results
    assert all(r.error is None for r in results), [r.error for r in results if r.error]
