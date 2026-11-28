# 1. Deploy with OIDC instead of a stored client secret

Status: accepted (2026-11-28)

## Context
CI has to deploy Sentinel analytics rules to Azure. The obvious way is a service principal client secret stored as a GitHub secret. Secrets expire, have to be rotated, and can leak through logs, screenshots or a compromised workflow.

## Decision
The deploy workflow logs in with GitHub's OIDC token and a federated credential on the service principal. The credential only trusts this repository (by immutable owner and repository ID) and only the `main` branch. The workflow runs on pushes to `main`, never on pull requests, and the service principal has Contributor on a single resource group.

## Consequences
- No Azure secret exists in the repo or in GitHub, so there is nothing to rotate or leak from the pipeline.
- To deploy, an attacker needs to push to `main`, which requires passing the required CI check.
- The credential is set up by hand in the portal, and it is tied to this repository, so a renamed or recreated repo needs a new credential.
- A client secret still exists for local lab use with the Azure CLI. It lives outside the repo with restricted permissions and has been rotated once as a precaution.
