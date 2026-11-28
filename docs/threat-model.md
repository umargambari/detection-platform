# Threat model

Scope: the detection pipeline in this repo (rules, CI gate, OIDC deploy) and the Azure lab it deploys to. Not a model of the monitored tenant.

## Assets
- The Sentinel workspace and the analytics rules in it
- The Azure subscription and the lab resource group
- The `main` branch, which is the only source of deployed rules
- The Entra audit logs the detections read

## Threats and controls

| # | Threat | Control | Evidence |
|---|---|---|---|
| 1 | A broken or noisy rule reaches production | Required CI check: lint, fixture tests, unit tests, KQL conversion and template rendering. Fixture folders with no matching rule fail the run | [CI gate blocking a bad rule](images/ci-gate-blocked.png) |
| 2 | Someone deploys to Azure without review | The deploy workflow runs only on pushes to `main`, which need the required check. Never on pull requests | `.github/workflows/deploy.yml` |
| 3 | The Azure credential leaks | No Azure secret is stored in the repo or in GitHub. Deploys use OIDC with a short-lived token ([ADR 1](adr/0001-oidc-instead-of-a-stored-secret.md)) | [OIDC deploy run](images/06-deploy-oidc-green.png) |
| 4 | The deploy identity is abused | Federated credential trusts one repository (immutable IDs) and one branch. The service principal has Contributor on a single resource group | Entra app registration |
| 5 | An attacker evades a rule by changing a value's format | Rules match prefixes, and fixtures are built from real log values. A real trailing-space bug was found and fixed this way | README, "A bug that only real data found" |
| 6 | Alert suppression hides a second attack | Known trade-off, documented in [ADR 2](adr/0002-alert-suppression-enabled.md) | |
| 7 | Runaway cost in the lab | Daily ingestion cap on the workspace, a budget alert, and a teardown script | `infra/main.bicep`, `scripts/teardown.sh` |

## Residual risks
- **Actions are pinned to major version tags**, not commit SHAs. A compromised upstream tag could run in the deploy job. Pinning to SHAs would remove this.
- **Detection latency is about 9 to 10 minutes** from event to alert. Most of it is Entra's export delay plus the 5 minute schedule.
- **Coverage is limited.** The free Entra tier gives audit logs but not sign-in logs, so sign-in based detections are out of reach. The Windows rules have no live log source ([ADR 3](adr/0003-deploy-only-azure-rules.md)).
- **Lab-only shortcuts.** The test admin user holds Owner on the subscription, and a client secret exists for local Azure CLI use. Neither would be acceptable in production.
- **One person, one branch.** There is no second reviewer on pull requests. The required check is the only gate.
