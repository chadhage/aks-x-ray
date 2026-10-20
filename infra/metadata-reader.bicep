targetScope = 'resourceGroup'

@description('Existing cloud AKS cluster. This template grants no Kubernetes data-plane access.')
param clusterName string

@description('Object ID of an existing assessment user, group, or service principal.')
param principalId string

@allowed([
  'User'
  'Group'
  'ServicePrincipal'
])
param principalType string

resource cluster 'Microsoft.ContainerService/managedClusters@2024-10-01' existing = {
  name: clusterName
}

var readerRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'acdd72a7-3385-48ef-bd42-f606fba81ae7')

resource metadataReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(cluster.id, principalId, readerRoleId)
  scope: cluster
  properties: {
    principalId: principalId
    principalType: principalType
    roleDefinitionId: readerRoleId
  }
}

output roleAssignmentId string = metadataReader.id
