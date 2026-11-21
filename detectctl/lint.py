"""Lint Sigma rules against this repository's quality bar."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from pathlib import Path

import yaml

REQUIRED_FIELDS = (
    "title", "id", "status", "description", "author",
    "date", "logsource", "detection", "falsepositives", "level",
)
VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
VALID_LEVEL = {"informational", "low", "medium", "high", "critical"}
ATTACK_TECHNIQUE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


@dataclass(frozen=True)
class Finding:
    path: Path
    message: str


def _load(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def lint_rule(path: Path) -> list[Finding]:
    """Return every problem found in one rule file."""
    try:
        data = _load(path)
    except (OSError, yaml.YAMLError) as exc:
        return [Finding(path, f"cannot read or parse YAML: {exc}")]
    if not isinstance(data, dict):
        return [Finding(path, "top level must be a mapping")]

    findings: list[Finding] = []

    def add(message: str) -> None:
        findings.append(Finding(path, message))

    for field in REQUIRED_FIELDS:
        if data.get(field) in (None, "", [], {}):
            add(f"missing required field: {field}")

    rule_id = data.get("id")
    if rule_id:
        try:
            uuid.UUID(str(rule_id))
        except ValueError:
            add("id must be a valid UUID")

    status = data.get("status")
    if status and str(status) not in VALID_STATUS:
        add(f"status must be one of {sorted(VALID_STATUS)}")

    level = data.get("level")
    if level and str(level) not in VALID_LEVEL:
        add(f"level must be one of {sorted(VALID_LEVEL)}")

    tags = data.get("tags")
    if not isinstance(tags, list) or not any(
        ATTACK_TECHNIQUE.match(str(tag)) for tag in tags
    ):
        add("tags must include an ATT&CK technique such as attack.t1059.001")

    detection = data.get("detection")
    if isinstance(detection, dict) and "condition" not in detection:
        add("detection must define a condition")

    return findings


def lint_paths(root: Path) -> tuple[int, list[Finding]]:
    """Lint every rule under root. Returns (rules checked, findings)."""
    files = sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml"))
    findings: list[Finding] = []
    seen_ids: dict[str, Path] = {}

    for path in files:
        findings.extend(lint_rule(path))
        try:
            data = _load(path)
        except (OSError, yaml.YAMLError):
            continue
        rule_id = data.get("id") if isinstance(data, dict) else None
        if rule_id:
            key = str(rule_id).lower()
            if key in seen_ids:
                findings.append(
                    Finding(path, f"duplicate id (also used by {seen_ids[key]})")
                )
            else:
                seen_ids[key] = path

    return len(files), findings
