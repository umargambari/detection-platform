"""Run each rule against its sample events and report whether it behaves."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import yaml

from .engine import UnsupportedRule, rule_matches


@dataclass(frozen=True)
class CaseResult:
    rule: Path
    case: str
    ok: bool
    detail: str = ""


def _rule_files(rules_dir: Path) -> list[Path]:
    return sorted(rules_dir.rglob("*.yml")) + sorted(rules_dir.rglob("*.yaml"))


def _run_case(rule_path: Path, rule: dict, fixture: Path, expected: bool) -> CaseResult:
    try:
        event = json.loads(fixture.read_text(encoding="utf-8"))
        if not isinstance(event, dict):
            return CaseResult(rule_path, fixture.name, False, "fixture must be a JSON object")
        actual = rule_matches(rule, event)
    except (OSError, json.JSONDecodeError) as exc:
        return CaseResult(rule_path, fixture.name, False, f"cannot read fixture: {exc}")
    except UnsupportedRule as exc:
        return CaseResult(rule_path, fixture.name, False, f"unsupported rule feature: {exc}")

    if actual == expected:
        return CaseResult(rule_path, fixture.name, True)
    if expected:
        return CaseResult(rule_path, fixture.name, False, "expected the rule to fire, but it did not")
    return CaseResult(rule_path, fixture.name, False, "expected the rule to stay silent, but it fired")


def run_rule_tests(rules_dir: Path, fixtures_dir: Path) -> list[CaseResult]:
    """Run every rule under rules_dir against fixtures_dir/<rule file name>/."""
    results: list[CaseResult] = []

    for rule_path in _rule_files(rules_dir):
        try:
            rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            results.append(CaseResult(rule_path, "(rule file)", False, f"cannot parse rule: {exc}"))
            continue
        if not isinstance(rule, dict):
            results.append(CaseResult(rule_path, "(rule file)", False, "top level must be a mapping"))
            continue

        folder = fixtures_dir / rule_path.stem
        positives = sorted(folder.glob("match*.json")) if folder.is_dir() else []
        negatives = sorted(folder.glob("nomatch*.json")) if folder.is_dir() else []
        if not positives or not negatives:
            results.append(CaseResult(
                rule_path, "(fixtures)", False,
                f"needs at least one match*.json and one nomatch*.json in {folder}",
            ))
            continue

        for fixture in positives:
            results.append(_run_case(rule_path, rule, fixture, expected=True))
        for fixture in negatives:
            results.append(_run_case(rule_path, rule, fixture, expected=False))

    known = {path.stem for path in _rule_files(rules_dir)}
    if known and fixtures_dir.is_dir():
        for folder in sorted(p for p in fixtures_dir.iterdir() if p.is_dir()):
            if folder.name.startswith((".", "_")) or folder.name in known:
                continue
            results.append(CaseResult(
                folder, "(orphan fixtures)", False,
                "fixtures folder has no matching rule file",
            ))

    return results
