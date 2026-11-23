from pathlib import Path

from detectctl.cli import main

RULES = str(Path(__file__).resolve().parent.parent / "rules")
RULE_COUNT = len(list(Path(RULES).rglob("*.yml")))


def test_convert_prints_kql(capsys):
    assert main(["convert", RULES]) == 0
    out = capsys.readouterr().out
    assert "SecurityEvent" in out
    assert f"{RULE_COUNT} rule(s) converted for azuremonitor, 0 failed" in out


def test_convert_target_xdr(capsys):
    assert main(["convert", RULES, "--target", "xdr"]) == 0
    assert "DeviceProcessEvents" in capsys.readouterr().out


def test_convert_writes_kql_files(tmp_path, capsys):
    out_dir = tmp_path / "kql"
    assert main(["convert", RULES, "--out", str(out_dir)]) == 0
    files = list(out_dir.glob("*.kql"))
    assert len(files) == RULE_COUNT
    assert all(f.read_text().startswith("SecurityEvent") for f in files)


def test_convert_missing_directory(capsys):
    assert main(["convert", "no/such/dir"]) == 2


def test_convert_reports_failures(tmp_path, capsys):
    (tmp_path / "bad.yml").write_text("title: [unclosed\n")
    assert main(["convert", str(tmp_path)]) == 1
    assert "FAIL  bad" in capsys.readouterr().out
