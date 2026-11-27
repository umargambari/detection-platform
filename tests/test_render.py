"""Tests for rendering Sigma rules into Sentinel analytics-rule ARM resources."""

import json
from pathlib import Path

import pytest

from detectctl.render import RenderError, render_rule, render_template

ROOT = Path(__file__).resolve().parent.parent
AZURE_RULES = ROOT / "rules" / "azure"
ENTRA_RULE = AZURE_RULES / "azure_auditlogs_credential_added_to_app.yml"
ENTRA_ID = "021cb8bd-d4af-43c7-bfa1-be726b838b24"

MINIMAL = """\
title: {title}
id: {id}
status: experimental
description: test rule
author: test
date: 2026-11-27
tags:
{tags}
logsource:
  product: azure
  service: auditlogs
detection:
  selection:
    OperationName: 'x'
  condition: selection
{level}
"""


def _write(tmp_path, *, tags=("attack.persistence", "attack.t1098.001"), level="medium"):
    tag_lines = "\n".join(f"  - {t}" for t in tags)
    level_line = f"level: {level}" if level else ""
    path = tmp_path / "rule.yml"
    path.write_text(
        MINIMAL.format(
            title="Test rule",
            id="11111111-2222-3333-4444-555555555555",
            tags=tag_lines,
            level=level_line,
        ),
        encoding="utf-8",
    )
    return path


def test_resource_identity_and_kind():
    resource = render_rule(ENTRA_RULE)
    assert resource["type"] == "Microsoft.SecurityInsights/alertRules"
    assert resource["kind"] == "Scheduled"
    assert resource["name"] == ENTRA_ID


def test_properties_come_from_the_sigma_rule():
    props = render_rule(ENTRA_RULE)["properties"]
    assert props["displayName"] == "Credential Added to Azure AD Application or Service Principal"
    assert "new secret or certificate" in props["description"]
    assert props["description"] == props["description"].strip()
    assert props["query"].startswith("AuditLogs")
    assert props["enabled"] is True
    assert props["tactics"] == ["Persistence"]
    assert props["techniques"] == ["T1098"]


def test_schedule_defaults_and_overrides():
    props = render_rule(ENTRA_RULE)["properties"]
    assert props["queryFrequency"] == "PT5M"
    assert props["queryPeriod"] == "PT1H"
    assert props["triggerOperator"] == "GreaterThan"
    assert props["triggerThreshold"] == 0
    assert props["suppressionEnabled"] is True
    assert props["suppressionDuration"] == "PT1H"
    custom = render_rule(ENTRA_RULE, frequency="PT15M", period="PT30M")["properties"]
    assert custom["queryFrequency"] == "PT15M"
    assert custom["queryPeriod"] == "PT30M"


@pytest.mark.parametrize(
    "level,expected",
    [
        ("informational", "Informational"),
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "High"),
    ],
)
def test_severity_mapping(tmp_path, level, expected):
    assert render_rule(_write(tmp_path, level=level))["properties"]["severity"] == expected


def test_missing_level_defaults_to_medium(tmp_path):
    assert render_rule(_write(tmp_path, level=None))["properties"]["severity"] == "Medium"


def test_technique_only_tags_give_no_tactics(tmp_path):
    props = render_rule(_write(tmp_path, tags=("attack.t1098.001",)))["properties"]
    assert props["tactics"] == []
    assert props["techniques"] == ["T1098"]


def test_tactics_use_sentinel_names_and_techniques_are_deduplicated(tmp_path):
    tags = ("attack.credential-access", "attack.defense-evasion", "attack.t1003.001", "attack.t1003.002")
    props = render_rule(_write(tmp_path, tags=tags))["properties"]
    assert props["tactics"] == ["CredentialAccess", "DefenseEvasion"]
    assert props["techniques"] == ["T1003"]


def test_template_wraps_rules_under_a_workspace_parameter():
    template = render_template(AZURE_RULES)
    assert template["parameters"]["workspaceName"]["type"] == "string"
    assert [r["name"] for r in template["resources"]] == [ENTRA_ID]
    scope = template["resources"][0]["scope"]
    assert scope.startswith("[format('Microsoft.OperationalInsights/workspaces/")


def test_template_is_json_serialisable():
    json.dumps(render_template(AZURE_RULES))


def test_template_reports_every_failing_rule(tmp_path):
    (tmp_path / "bad.yml").write_text("title: [unclosed", encoding="utf-8")
    with pytest.raises(RenderError) as exc:
        render_template(tmp_path)
    assert "bad.yml" in str(exc.value)


def test_template_rejects_a_folder_without_rules(tmp_path):
    with pytest.raises(RenderError):
        render_template(tmp_path)
