targetScope = 'resourceGroup'

param location string = resourceGroup().location
param workspaceName string = 'law-detection-lab'
@description('Daily ingestion cap in GB, to protect the free credit')
param dailyQuotaGb int = 1

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    workspaceCapping: { dailyQuotaGb: dailyQuotaGb }
  }
}

resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  name: 'default'
  scope: workspace
  properties: {}
}

output workspaceId string = workspace.id
output workspaceName string = workspace.name
