"""Sigma -> Microsoft Sentinel analytics-rule rendering (ARM JSON)."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

from detectctl.convert import ConversionError, convert_rule

ALERT_RULE_TYPE = "Microsoft.SecurityInsights/alertRules"
ALERT_RULE_API = "2023-02-01"
SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
SCOPE = "[format('Microsoft.OperationalInsights/workspaces/{0}', parameters('workspaceName'))]"

# Sentinel has no "critical"; the closest severity is High.
SEVERITY = {
    "informational": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "High",
}

# Sigma attack.<tactic> tag -> Sentinel tactic name.
TACTICS = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "ResourceDevelopment",
    "initial-access": "InitialAccess",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "PrivilegeEscalation",
    "defense-evasion": "DefenseEvasion",
    "credential-access": "CredentialAccess",
    "discovery": "Discovery",
    "lateral-movement": "LateralMovement",
    "collection": "Collection",
    "command-and-control": "CommandAndControl",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

# attack.t1098 or attack.t1098.001 -> T1098 (Sentinel wants the parent technique)
_TECHNIQUE = re.compile(r"^t(\d{4})(?:\.\d{3})?$")


class RenderError(Exception):
    """A rule could not be rendered."""


def _load(path: Path):
    try:
        collection = SigmaCollection.from_yaml(Path(path).read_text(encoding="utf-8"))
    except (SigmaError, yaml.YAMLError, OSError) as exc:
        raise RenderError(str(exc)) from exc
    if len(collection.rules) != 1:
        raise RenderError(f"expected 1 rule, got {len(collection.rules)}")
    return collection.rules[0]


def _attack(tags) -> tuple[list[str], list[str]]:
    tactics: list[str] = []
    techniques: list[str] = []
    for tag in tags or []:
        if tag.namespace != "attack":
            continue
        name = tag.name.lower()
        if name in TACTICS and TACTICS[name] not in tactics:
            tactics.append(TACTICS[name])
            continue
        match = _TECHNIQUE.match(name)
        if match:
            technique = f"T{match.group(1)}"
            if technique not in techniques:
                techniques.append(technique)
    return tactics, techniques


def render_rule(
    path: Path,
    frequency: str = "PT5M",
    period: str = "PT1H",
    suppression: str = "PT1H",
) -> dict:
    """Render one Sigma rule file as a Sentinel scheduled analytics-rule resource."""
    rule = _load(path)
    if rule.id is None:
        raise RenderError("rule has no id (needed as the Sentinel resource name)")
    try:
        query = convert_rule(Path(path), "azuremonitor")
    except ConversionError as exc:
        raise RenderError(str(exc)) from exc
    level = rule.level.name.lower() if rule.level is not None else "medium"
    tactics, techniques = _attack(rule.tags)
    return {
        "type": ALERT_RULE_TYPE,
        "apiVersion": ALERT_RULE_API,
        "name": str(rule.id),
        "scope": SCOPE,
        "kind": "Scheduled",
        "properties": {
            "displayName": rule.title,
            "description": (rule.description or "").strip(),
            "severity": SEVERITY.get(level, "Medium"),
            "enabled": True,
            "query": query,
            "queryFrequency": frequency,
            "queryPeriod": period,
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "incidentConfiguration": {"createIncident": True},
            "suppressionEnabled": True,
            "suppressionDuration": suppression,
            "tactics": tactics,
            "techniques": techniques,
        },
    }


def render_template(root: Path, **schedule) -> dict:
    """Render every rule under root into one ARM template. Raises on any failure."""
    root = Path(root)
    paths = sorted(root.rglob("*.yml"))
    if not paths:
        raise RenderError(f"no rules found under {root}")
    resources, errors = [], []
    for path in paths:
        try:
            resources.append(render_rule(path, **schedule))
        except RenderError as exc:
            errors.append(f"{path}: {exc}")
    if errors:
        raise RenderError("\n".join(errors))
    return {
        "$schema": SCHEMA,
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspaceName": {
                "type": "string",
                "metadata": {"description": "Log Analytics workspace with Sentinel enabled"},
            }
        },
        "resources": resources,
    }
