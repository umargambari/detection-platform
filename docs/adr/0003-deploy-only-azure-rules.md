# 3. Lint, test and convert every rule, but deploy only `rules/azure`

Status: accepted (2026-11-28)

## Context
The repo holds Azure (Entra audit log) rules and Windows process-creation rules. Sentinel analytics rules are validated against the workspace schema. The Windows rules query tables such as `SecurityEvent`, which this lab workspace does not ingest, so deploying them is expected to be rejected (not confirmed by trying).

## Decision
CI lints, fixture-tests and converts all rules to KQL. Only `rules/azure` is rendered to an ARM template and deployed.

## Consequences
- Every rule is held to the same quality bar, and the deployable ones are proven live.
- The Windows rules are verified by fixtures only, not on a live log source, and the README says so.
- To deploy them later, the workspace needs a Windows log source first, for example a short-lived VM that is torn down the same day.
