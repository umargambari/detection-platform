import json
from pathlib import Path

import yaml

from detectctl.cli import main
from detectctl.ruletest import run_rule_tests

REPO_ROOT = Path(__file__).resolve().parent.parent

RULE = {
    "title": "demo",
    "detection": {"sel": {"CommandLine|contains": " -enc "}, "condition": "sel"},
}

GOOD = {
    "match.json": {"CommandLine": "x -enc y"},
    "nomatch.json": {"CommandLine": "x"},
}


def make_project(tmp_path: Path, fixtures: dict, rule: dict = RULE):
    rules = tmp_path / "rules"
    folder = tmp_path / "fixtures" / "demo"
    rules.mkdir()
    folder.mkdir(parents=True)
    (rules / "demo.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    for name, content in fixtures.items():
        text = content if isinstance(content, str) else json.dumps(content)
        (folder / name).write_text(text, encoding="utf-8")
    return rules, tmp_path / "fixtures"


def failures(results):
    return [r for r in results if not r.ok]


def test_all_cases_pass(tmp_path):
    rules, fixtures = make_project(tmp_path, GOOD)
    results = run_rule_tests(rules, fixtures)
    assert len(results) == 2
    assert failures(results) == []


def test_missed_detection_is_reported(tmp_path):
    fixtures_data = {**GOOD, "match.json": {"CommandLine": "nothing here"}}
    rules, fixtures = make_project(tmp_path, fixtures_data)
    bad = failures(run_rule_tests(rules, fixtures))
    assert len(bad) == 1
    assert "fire" in bad[0].detail


def test_false_positive_is_reported(tmp_path):
    fixtures_data = {**GOOD, "nomatch.json": {"CommandLine": "x -enc y"}}
    rules, fixtures = make_project(tmp_path, fixtures_data)
    bad = failures(run_rule_tests(rules, fixtures))
    assert len(bad) == 1
    assert "silent" in bad[0].detail


def test_rule_without_any_fixtures_fails(tmp_path):
    rules, fixtures = make_project(tmp_path, {})
    bad = failures(run_rule_tests(rules, fixtures))
    assert len(bad) == 1
    assert "match*.json" in bad[0].detail


def test_rule_without_negative_fixture_fails(tmp_path):
    rules, fixtures = make_project(tmp_path, {"match.json": {"CommandLine": "x -enc y"}})
    assert len(failures(run_rule_tests(rules, fixtures))) == 1


def test_unsupported_rule_fails_loudly(tmp_path):
    rule = {"title": "demo", "detection": {"sel": {"CommandLine": "who*"}, "condition": "sel"}}
    rules, fixtures = make_project(tmp_path, GOOD, rule=rule)
    bad = failures(run_rule_tests(rules, fixtures))
    assert bad
    assert all("unsupported" in r.detail for r in bad)


def test_malformed_fixture_is_reported(tmp_path):
    rules, fixtures = make_project(tmp_path, {**GOOD, "match.json": "{not json"})
    bad = failures(run_rule_tests(rules, fixtures))
    assert len(bad) == 1
    assert "cannot read fixture" in bad[0].detail


def test_non_object_fixture_is_reported(tmp_path):
    rules, fixtures = make_project(tmp_path, {**GOOD, "match.json": "[1, 2]"})
    bad = failures(run_rule_tests(rules, fixtures))
    assert len(bad) == 1
    assert "JSON object" in bad[0].detail


def test_repository_rules_pass_their_tests():
    results = run_rule_tests(REPO_ROOT / "rules", REPO_ROOT / "tests" / "fixtures")
    assert results
    assert failures(results) == []


def test_cli_test_exit_codes(tmp_path, capsys):
    rules, fixtures = make_project(tmp_path, GOOD)
    assert main(["test", str(rules), "--fixtures", str(fixtures)]) == 0
    assert "2 passed, 0 failed" in capsys.readouterr().out

    (fixtures / "demo" / "match.json").write_text('{"CommandLine": "nope"}', encoding="utf-8")
    assert main(["test", str(rules), "--fixtures", str(fixtures)]) == 1
    assert "FAIL" in capsys.readouterr().out

    assert main(["test", str(tmp_path / "missing")]) == 2


def test_cli_test_with_no_rules_is_an_error(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["test", str(empty)]) == 2


def _add_orphan(fixtures: Path) -> None:
    orphan = fixtures / "renamed_rule"
    orphan.mkdir()
    (orphan / "match.json").write_text("{}", encoding="utf-8")


def test_fixtures_folder_without_a_rule_is_reported(tmp_path):
    rules, fixtures = make_project(tmp_path, GOOD)
    _add_orphan(fixtures)
    bad = failures(run_rule_tests(rules, fixtures))
    assert len(bad) == 1
    assert bad[0].rule.name == "renamed_rule"
    assert "no matching rule" in bad[0].detail


def test_cli_exits_1_when_fixtures_have_no_rule(tmp_path):
    rules, fixtures = make_project(tmp_path, GOOD)
    _add_orphan(fixtures)
    assert main(["test", str(rules), "--fixtures", str(fixtures)]) == 1
