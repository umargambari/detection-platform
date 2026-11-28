import json
from pathlib import Path

from detectctl.cli import main

ROOT = Path(__file__).resolve().parent.parent
AZURE_RULES = ROOT / "rules" / "azure"
RULE_COUNT = len(list(AZURE_RULES.rglob("*.yml")))


def test_render_prints_template_json(capsys):
    assert main(["render", str(AZURE_RULES)]) == 0
    template = json.loads(capsys.readouterr().out)
    assert len(template["resources"]) == RULE_COUNT


def test_render_writes_a_file_and_creates_parent_dirs(tmp_path, capsys):
    out = tmp_path / "nested" / "analytics.json"
    assert main(["render", str(AZURE_RULES), "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["resources"]
    assert f"{RULE_COUNT} rule(s) rendered" in capsys.readouterr().out


def test_render_schedule_options(tmp_path):
    out = tmp_path / "a.json"
    code = main(["render", str(AZURE_RULES), "--out", str(out),
                 "--frequency", "PT15M", "--period", "PT30M"])
    assert code == 0
    props = json.loads(out.read_text(encoding="utf-8"))["resources"][0]["properties"]
    assert props["queryFrequency"] == "PT15M"
    assert props["queryPeriod"] == "PT30M"


def test_render_missing_directory_exits_2(tmp_path):
    assert main(["render", str(tmp_path / "nope")]) == 2


def test_render_empty_directory_exits_2(tmp_path):
    assert main(["render", str(tmp_path)]) == 2


def test_render_bad_rule_exits_1_and_writes_nothing(tmp_path, capsys):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "bad.yml").write_text("title: [unclosed", encoding="utf-8")
    out = tmp_path / "out.json"
    assert main(["render", str(rules), "--out", str(out)]) == 1
    assert not out.exists()
    assert "bad.yml" in capsys.readouterr().out
