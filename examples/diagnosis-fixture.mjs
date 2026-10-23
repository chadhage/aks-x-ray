import { demoEvidence } from './demo.mjs';
import { defaultScope } from '../src/evidence.mjs';

export const diagnosisTimestamp = '2026-10-23T11:00:00.000Z';
export const diagnosisTenant = '10000000-0000-0000-0000-000000000001';
export const diagnosisSubscriptions = ['00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002'];
export const diagnosisPrincipal = '20000000-0000-0000-0000-000000000001';
export const diagnosisRole = '30000000-0000-0000-0000-000000000001';
export const dependencyStorageId = `/subscriptions/${diagnosisSubscriptions[1]}/resourceGroups/shared/providers/Microsoft.Storage/storageAccounts/sharedstorage`;
export const managedIdentityId = `/subscriptions/${diagnosisSubscriptions[0]}/resourceGroups/shared/providers/Microsoft.ManagedIdentity/userAssignedIdentities/shared-identity`;

export function diagnosisEvidence({ cluster = 'xray-demo', subscription = diagnosisSubscriptions[0] } = {}) {
  const evidence = demoEvidence();
  evidence.collectedAt = diagnosisTimestamp;
  evidence.target = { ...evidence.target, tenant: diagnosisTenant, subscription, cluster, context: `context-${cluster}` };
  evidence.scope = defaultScope({
    strategies: ['azure', 'kubernetes', 'iam', 'iam-inventory', 'policy', 'defender', 'advisor', 'dependencies'],
    authorization: { readOnly: true }, authorizedSubscriptions: [...diagnosisSubscriptions],
    scenario: { name: 'Sensitive production API', profile: 'production', apiAccess: 'private', minimumReplicas: 3, minimumZones: 3 }
  });
  for (const record of Object.values(evidence.sources)) record.collectedAt = diagnosisTimestamp;
  evidence.sources.accounts = { status: 'ok', collectedAt: diagnosisTimestamp, commands: [],
    data: { items: diagnosisSubscriptions.map((id) => ({ id, tenantId: diagnosisTenant, state: 'Enabled' })) } };
  const arm = evidence.sources.cluster.data;
  arm.name = cluster;
  arm.id = `/subscriptions/${subscription}/resourceGroups/rg-xray-demo/providers/Microsoft.ContainerService/managedClusters/${cluster}`;
  arm.fqdn = `${cluster}.example.invalid`;
  arm.identity = { type: 'UserAssigned', tenantId: diagnosisTenant, principalId: diagnosisPrincipal,
    userAssignedIdentities: { [managedIdentityId]: { principalId: diagnosisPrincipal, clientId: '40000000-0000-0000-0000-000000000001' } } };
  arm.linkedResourceIds = [managedIdentityId];
  evidence.sources.context.data.server = `https://${arm.fqdn}`;
  for (const id of ['deployments', 'pods']) {
    const spec = evidence.sources[id].data.items[0].pod.spec;
    spec.automountServiceAccountToken = true;
  }
  evidence.sources.serviceaccounts.data.items[0].automountServiceAccountToken = true;
  Object.assign(evidence.sources.services.data.items[0], {
    type: 'LoadBalancer', internal: 'false', loadBalancerIngress: [{ hostname: 'public.example.invalid' }]
  });
  evidence.sources.roles = { status: 'ok', collectedAt: diagnosisTimestamp, commands: [], data: { items: [{
    kind: 'Role', metadata: { name: 'secret-reader', namespace: 'payments' },
    rules: [{ apiGroups: [''], resources: ['secrets'], verbs: ['get', 'list'] }]
  }] } };
  evidence.sources.rolebindings = { status: 'ok', collectedAt: diagnosisTimestamp, commands: [], data: { items: [{
    kind: 'RoleBinding', metadata: { name: 'checkout-reader', namespace: 'payments' },
    roleRef: { kind: 'Role', name: 'secret-reader' },
    subjects: [{ kind: 'ServiceAccount', name: 'checkout', namespace: 'payments' }]
  }] } };
  evidence.sources.relatedResources.data.items = [
    { id: managedIdentityId, name: 'shared-identity', type: 'Microsoft.ManagedIdentity/userAssignedIdentities',
      supported: true, configuration: { tenantId: diagnosisTenant, principalId: diagnosisPrincipal, clientId: '40000000-0000-0000-0000-000000000001' }, linkedResourceIds: [] },
    { id: dependencyStorageId, name: 'sharedstorage', type: 'Microsoft.Storage/storageAccounts',
      supported: true, configuration: { supportsHttpsTrafficOnly: true, minimumTlsVersion: 'TLS1_2', allowBlobPublicAccess: false }, linkedResourceIds: [] }
  ];
  evidence.sources.roleAssignments.data.items = [{
    id: `${dependencyStorageId}/providers/Microsoft.Authorization/roleAssignments/50000000-0000-0000-0000-000000000001`,
    scope: dependencyStorageId, roleDefinitionId: `/subscriptions/${diagnosisSubscriptions[1]}/providers/Microsoft.Authorization/roleDefinitions/${diagnosisRole}`,
    principalId: diagnosisPrincipal, principalType: 'ServicePrincipal', hasCondition: false
  }];
  evidence.sources.roleDefinitions = { status: 'ok', collectedAt: diagnosisTimestamp, commands: [], data: { items: [{
    id: `/subscriptions/${diagnosisSubscriptions[1]}/providers/Microsoft.Authorization/roleDefinitions/${diagnosisRole}`,
    name: diagnosisRole, roleName: 'Synthetic scoped blob reader',
    permissions: [{ actions: [], notActions: [], dataActions: ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'], notDataActions: [] }]
  }] } };
  evidence.sources.federatedCredentials = { status: 'ok', collectedAt: diagnosisTimestamp, commands: [], data: { items: [] } };
  return evidence;
}

export function diagnosisConfig(strategies = ['graph', 'exposure', 'attack-paths']) {
  const evidence = diagnosisEvidence();
  const { tenant, ...target } = evidence.target;
  return {
    tenant: diagnosisTenant, subscriptions: [...diagnosisSubscriptions], authorization: { readOnly: true },
    strategies: [...evidence.scope.strategies], scenario: { ...evidence.scope.scenario,
      businessCriticality: 'high', dataSensitivity: 'confidential', applicationExposure: 'public', assumedCompromise: [] },
    targets: [target],
    assessment: { strategies, stages: ['passive'] }
  };
}
