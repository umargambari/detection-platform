#!/usr/bin/env bash
# Tear down the detection-platform lab: deletes the resource group and everything in it.
# Usage: scripts/teardown.sh [--dry-run] [resource-group]
set -euo pipefail

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then DRY_RUN=1; shift; fi
RG="${1:-rg-detection-lab}"

echo "Resource group: $RG"
az group show -n "$RG" --query "{name:name, location:location, state:properties.provisioningState}" -o table
echo
echo "Resources that will be deleted:"
az resource list -g "$RG" --query "[].{Name:name, ResourceType:type}" -o table

if [ "$DRY_RUN" -eq 1 ]; then
  echo
  echo "Dry run only. Nothing was deleted."
  exit 0
fi

echo
read -rp "Type the resource group name to confirm deletion: " confirm
if [ "$confirm" != "$RG" ]; then
  echo "Aborted."
  exit 1
fi
az group delete -n "$RG" --yes --no-wait
echo "Deletion started."
echo "Not removed by this script (Entra is tenant-level): the audit-to-law diagnostic setting,"
echo "the demo-victim-app and sp-detection-lab app registrations, and the labadmin user."
