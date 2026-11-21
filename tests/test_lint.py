import copy
from pathlib import Path

import pytest
import yaml

from detectctl.cli import main
from detectctl.lint import lint_paths, lint_rule

REPO_ROOT = Path(__file__).resolve().parent.parent

VALID_RULE = {
    "title": "Example rule",
    "id": "11111111-2222-4333-8444-555555555555",
    "status": "experimental",
    "description": "Example description.",
    "author": "Tester",
    "date": "2026-11-21",
    "tags": ["attack.execution", "attack.t1059.001"],
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {
        "selection": {"Image|endswith": "\\powershell.exe"},
        "condition": "selection",
    },
    "falsepositives": ["Admin scripts"],
    "level": "medium",
}


def write_rule(directory: Path, name: str = "rule.yml", **overrides) -> Path:
    rule = copy.deepcopy(VALID_RULE)
    rule.update(overrides)
    path = directory / name
    path.write_text(yaml.safe_dump(rule), encoding="utf-8")
    return path


def messages(path: Path) -> list[str]:
    return [finding.message for finding in lint_rule(path)]


def test_valid_rule_has_no_findings(tmp_path):
    assert lint_rule(write_rule(tmp_path)) == []


@pytest.mark.parametrize(
    "field", ["title", "id", "description", "author", "falsepositives", "level"]
)
def test_missing_field_is_flagged(tmp_path, field):
    path = write_rule(tmp_path, **{field: None})
    assert f"missing required field: {field}" in messages(path)


def test_invalid_uuid_is_flagged(tmp_path):
    assert "id must be a valid UUID" in messages(write_rule(tmp_path, id="not-a-uuid"))


def test_invalid_level_is_flagged(tmp_path):
    found = messages(write_rule(tmp_path, level="severe"))
    assert any(m.startswith("level must be one of") for m in found)


def test_missing_attack_technique_is_flagged(tmp_path):
    found = messages(write_rule(tmp_path, tags=["attack.execution"]))
    assert any("ATT&CK technique" in m for m in found)


def test_missing_condition_is_flagged(tmp_path):
    rule = write_rule(tmp_path, detection={"selection": {"Image": "x"}})
    assert "detection must define a condition" in messages(rule)


def test_unparseable_yaml_is_flagged(tmp_path):
    path = tmp_path / "broken.yml"
    path.write_text("title: [unclosed", encoding="utf-8")
    assert any("cannot read or parse YAML" in m for m in messages(path))


def test_duplicate_ids_are_flagged(tmp_path):
    write_rule(tmp_path, "a.yml")
    write_rule(tmp_path, "b.yml")
    _, findings = lint_paths(tmp_path)
    assert any("duplicate id" in f.message for f in findings)


def test_repository_rules_are_clean():
    checked, findings = lint_paths(REPO_ROOT / "rules")
    assert checked >= 1
    assert findings == []


def test_cli_exit_codes(tmp_path, capsys):
    assert main(["lint", str(tmp_path / "missing")]) == 2
    write_rule(tmp_path)
    assert main(["lint", str(tmp_path)]) == 0
    write_rule(tmp_path, "bad.yml", id="not-a-uuid")
    assert main(["lint", str(tmp_path)]) == 1
    assert "id must be a valid UUID" in capsys.readouterr().out
