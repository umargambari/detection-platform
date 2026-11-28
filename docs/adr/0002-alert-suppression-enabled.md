# 2. Keep alert suppression on for the lab rules

Status: accepted (2026-11-28)

## Context
One administrative action in Entra writes several audit rows within the same second. With a 5 minute schedule and a 1 hour lookback, an unsuppressed rule would raise repeated alerts for a single event and make the lab hard to read.

## Decision
Rendered rules enable suppression for 1 hour (`suppressionDuration: PT1H`). The renderer exposes frequency and period as options, so a rule can be tuned.

## Consequences
- One action produces one alert and one incident, which keeps the demo readable.
- **Trade-off:** after an alert fires, the rule stops running for an hour. A second, separate attack on the same detection inside that window is not alerted on. That is acceptable for a lab and not for production.
- A production deployment should tune suppression per rule, or turn it off and group alerts by entity instead.
