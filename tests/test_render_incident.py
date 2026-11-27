from pathlib import Path

from detectctl.render import render_rule

RULE = (
    Path(__file__).resolve().parents[1]
    / "rules/azure/azure_auditlogs_credential_added_to_app.yml"
)


def test_rule_creates_incident():
    props = render_rule(RULE)["properties"]
    assert props["incidentConfiguration"] == {"createIncident": True}
