import { defaultScope } from '../src/evidence.mjs';
import { requiredSources } from '../src/collector.mjs';
import { activeSources, projectSource, scopeProjection } from '../src/projection.mjs';
import { catalogVersion, catalogDigest, toolVersion } from '../src/catalog.mjs';

export const demoTimestamp = '2026-10-20T12:00:00.000Z';

export function demoRaw(platform = 'cloud') {
  const metadata = (name, namespace = 'payments', labels = {}) => ({ name, namespace, labels, generation: 1 });
  const list = (...items) => ({ items });
  const podSpec = {
    nodeSelector: { 'kubernetes.io/os': 'linux' }, nodeName: 'demo-node-1', serviceAccountName: 'checkout',
    securityContext: { runAsNonRoot: true, runAsUser: 10001, seccompProfile: { type: 'RuntimeDefault' } },
    containers: [{
      name: 'checkout', image: 'example.invalid/checkout:latest',
      resources: { requests: { cpu: '200m', memory: '256Mi' }, limits: { cpu: '100m', memory: '512Mi' } },
      securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: ['ALL'] } },
      readinessProbe: { httpGet: { path: '/ready', port: 8080 } },
      livenessProbe: { httpGet: { path: '/health', port: 8080 } }
    }]
  };
  const cloud = {
    id: '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-xray-demo/providers/Microsoft.ContainerService/managedClusters/xray-demo',
    name: 'xray-demo', type: 'Microsoft.ContainerService/managedClusters', location: 'eastus2',
    fqdn: 'aks-xray-demo.example.invalid', kubernetesVersion: '1.34.1', currentKubernetesVersion: '1.34.1',
    enableRbac: true, disableLocalAccounts: true, aadProfile: { managed: true }, sku: { name: 'Base', tier: 'Standard' },
    apiServerAccessProfile: { enablePrivateCluster: false, authorizedIpRanges: ['203.0.113.0/24'] },
    networkProfile: { networkPlugin: 'azure', networkPluginMode: 'overlay', networkDataplane: 'cilium',
      podCidr: '10.244.0.0/16', serviceCidr: '10.0.0.0/16', dnsServiceIP: '10.0.0.10', outboundType: 'userDefinedRouting' },
    oidcIssuerProfile: { enabled: true },
    securityProfile: { workloadIdentity: { enabled: true }, defender: { securityMonitoring: { enabled: true } } },
    addonProfiles: { azurepolicy: { enabled: true }, omsagent: { enabled: false } },
    azureMonitorProfile: { metrics: { enabled: true } },
    autoUpgradeProfile: { upgradeChannel: 'stable', nodeOSUpgradeChannel: 'NodeImage' },
    nodeProvisioningProfile: { mode: 'Manual' }
  };
  const dependencyId = (type, name) => `/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-xray-demo/providers/${type}/${name}`;
  const nsgId = dependencyId('Microsoft.Network/networkSecurityGroups', 'demo-nsg');
  return {
    context: platform === 'cloud' ? 'https://aks-xray-demo.example.invalid:443' : 'https://10.42.0.10:6443',
    cluster: platform === 'cloud' ? cloud : {
      id: '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-xray-demo/providers/Microsoft.Kubernetes/connectedClusters/xray-demo/providers/Microsoft.HybridContainerService/provisionedClusterInstances/default',
      name: 'default', type: 'Microsoft.HybridContainerService/provisionedClusterInstances', location: 'eastus',
      properties: { kubernetesVersion: '1.32.6', provisioningState: 'Succeeded',
        controlPlane: { count: 3, controlPlaneEndpoint: { hostIP: '10.42.0.10' } } }
    },
    nodes: list({ kind: 'Node', metadata: { name: 'demo-node-1', labels: { 'kubernetes.io/os': 'linux' } },
      status: { nodeInfo: { operatingSystem: 'linux', osImage: 'Azure Linux', kubeletVersion: 'v1.34.1' },
        conditions: [{ type: 'Ready', status: 'True' }, ...['MemoryPressure', 'DiskPressure', 'PIDPressure'].map((type) => ({ type, status: 'False' }))] } }),
    namespaces: list({ kind: 'Namespace', metadata: { name: 'payments', labels: { 'pod-security.kubernetes.io/enforce': 'restricted' } } }),
    deployments: list({ kind: 'Deployment', metadata: metadata('checkout', 'payments', { app: 'checkout' }),
      spec: { replicas: 2, template: { metadata: { labels: { app: 'checkout' } }, spec: podSpec } },
      status: { observedGeneration: 1, availableReplicas: 1 } }),
    pods: list({ kind: 'Pod', metadata: { ...metadata('checkout-example', 'payments', { app: 'checkout' }),
      ownerReferences: [{ kind: 'ReplicaSet', name: 'checkout-example' }] },
    spec: podSpec, status: { phase: 'Running', containerStatuses: [{ name: 'checkout', ready: true, restartCount: 0 }] } }),
    statefulsets: list(), daemonsets: list(), jobs: list(), cronjobs: list(),
    nodepools: [
      { name: 'system', mode: 'System', count: 3, nodeTaints: ['CriticalAddonsOnly=true:NoSchedule'], availabilityZones: ['1', '2', '3'] },
      { name: 'apps', mode: 'User', count: 2, enableAutoScaling: true, minCount: 2, maxCount: 5, availabilityZones: ['1', '2', '3'] }
    ],
    networkpolicies: list({ kind: 'NetworkPolicy', metadata: metadata('default-deny'),
      spec: { podSelector: {}, policyTypes: ['Ingress', 'Egress'], ingress: [], egress: [] } }),
    services: list({ kind: 'Service', metadata: metadata('checkout'),
      spec: { type: 'ClusterIP', clusterIP: '10.0.12.10', selector: { app: 'checkout' }, ports: [{ port: 80, targetPort: 8080 }] } }),
    endpointslices: list({ kind: 'EndpointSlice', metadata: metadata('checkout-example', 'payments', { 'kubernetes.io/service-name': 'checkout' }),
      endpoints: [{ addresses: ['10.244.0.5'], conditions: { ready: true } }] }),
    ingresses: list({ kind: 'Ingress', metadata: metadata('checkout'), spec: { rules: [{ host: 'checkout.example.invalid' }], tls: [] } }),
    pdbs: list({ kind: 'PodDisruptionBudget', metadata: metadata('checkout'),
      spec: { minAvailable: '100%', selector: { matchLabels: { app: 'checkout' } } }, status: { expectedPods: 2, disruptionsAllowed: 0 } }),
    pvcs: list({ kind: 'PersistentVolumeClaim', metadata: metadata('orders'),
      spec: { storageClassName: 'managed-csi', accessModes: ['ReadWriteOnce'] }, status: { phase: 'Bound' } }),
    pvs: list({ kind: 'PersistentVolume', metadata: { name: 'orders-demo' },
      spec: { storageClassName: 'managed-csi', persistentVolumeReclaimPolicy: 'Retain', csi: { driver: 'disk.csi.azure.com' } } }),
    storageclasses: list({ kind: 'StorageClass', metadata: { name: 'managed-csi' },
      provisioner: 'disk.csi.azure.com', volumeBindingMode: 'WaitForFirstConsumer', allowVolumeExpansion: true, reclaimPolicy: 'Delete' }),
    hpas: list({ kind: 'HorizontalPodAutoscaler', metadata: metadata('checkout'),
      spec: { minReplicas: 2, maxReplicas: 5, scaleTargetRef: { kind: 'Deployment', name: 'checkout' } } }),
    serviceaccounts: list({ kind: 'ServiceAccount', metadata: metadata('checkout'), automountServiceAccountToken: false }),
    resourcequotas: list({ kind: 'ResourceQuota', metadata: metadata('tenant'), spec: { hard: { 'requests.cpu': '4', 'requests.memory': '8Gi' } } }),
    limitranges: list({ kind: 'LimitRange', metadata: metadata('defaults'), spec: { limits: [{ type: 'Container', default: { cpu: '500m', memory: '512Mi' } }] } }),
    clusterrolebindings: list({ kind: 'ClusterRoleBinding', metadata: { name: 'demo-break-glass' },
      roleRef: { kind: 'ClusterRole', name: 'cluster-admin' }, subjects: [{ kind: 'Group', name: 'demo-privileged-operators' }] }),
    roles: list(), rolebindings: list(),
    clusterroles: list({ kind: 'ClusterRole', metadata: { name: 'cluster-admin' },
      rules: [{ apiGroups: ['*'], resources: ['*'], verbs: ['*'] }] }),
    validatingwebhooks: list({ kind: 'ValidatingWebhookConfiguration', metadata: { name: 'demo-admission' },
      webhooks: [{ name: 'policy.example.invalid', failurePolicy: 'Fail', sideEffects: 'None', timeoutSeconds: 10,
        rules: [{ apiGroups: [''], apiVersions: ['v1'], resources: ['pods'], operations: ['CREATE', 'UPDATE'] }] }] }),
    mutatingwebhooks: list(),
    accounts: { id: '00000000-0000-0000-0000-000000000001', tenantId: '10000000-0000-0000-0000-000000000001', state: 'Enabled' },
    roleAssignments: [{ id: 'synthetic-reader-assignment', scope: cloud.id, principalId: 'synthetic-operator',
      principalType: 'Group', roleDefinitionId: '/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7' }],
    policyStates: [{ resourceId: cloud.id, complianceState: 'Compliant', timestamp: demoTimestamp, policyAssignmentId: 'synthetic-assignment' }],
    defenderPricing: { name: 'Containers', pricingTier: 'Standard' },
    defenderAssessments: [{ name: 'synthetic-assessment', status: { code: 'Healthy' }, resourceDetails: { id: cloud.id } }],
    advisorRecommendations: [{ id: 'synthetic-recommendation', category: 'Performance', impact: 'Low', resourceMetadata: { resourceId: cloud.id } }],
    relatedResources: [
      { id: dependencyId('Microsoft.ContainerRegistry/registries', 'demoregistry'), name: 'demoregistry', type: 'Microsoft.ContainerRegistry/registries',
        properties: { adminUserEnabled: false, publicNetworkAccess: 'Disabled' } },
      { id: dependencyId('Microsoft.KeyVault/vaults', 'demo-vault'), name: 'demo-vault', type: 'Microsoft.KeyVault/vaults',
        properties: { enableSoftDelete: true, enablePurgeProtection: true, enableRbacAuthorization: true, publicNetworkAccess: 'Disabled' } },
      { id: dependencyId('Microsoft.Storage/storageAccounts', 'demostorage'), name: 'demostorage', type: 'Microsoft.Storage/storageAccounts',
        properties: { supportsHttpsTrafficOnly: true, minimumTlsVersion: 'TLS1_2', allowBlobPublicAccess: false, allowSharedKeyAccess: false } },
      { id: nsgId, name: 'demo-nsg', type: 'Microsoft.Network/networkSecurityGroups', properties: { securityRules: [] } },
      { id: dependencyId('Microsoft.Network/virtualNetworks', 'demo-vnet/subnets/aks'), name: 'aks', type: 'Microsoft.Network/virtualNetworks/subnets',
        properties: { addressPrefix: '10.10.0.0/24', networkSecurityGroup: { id: nsgId } } }
    ],
    events: list({ kind: 'Event', metadata: metadata('demo-warning'), type: 'Warning', reason: 'FailedScheduling', count: 1,
      lastTimestamp: demoTimestamp, message: 'This message is intentionally not exported.', involvedObject: { kind: 'Pod', name: 'checkout-example', namespace: 'payments' } }),
    diagnostics: { value: [{ name: 'audit-routing', workspaceId: '/subscriptions/demo/resourceGroups/demo/providers/Microsoft.OperationalInsights/workspaces/demo',
      logs: [{ category: 'kube-audit-admin', enabled: true }] }] },
    maintenance: ['aksManagedAutoUpgradeSchedule', 'aksManagedNodeOSUpgradeSchedule'].map((name) => ({
      name, maintenanceWindow: { durationHours: 4, utcOffset: '+00:00', startTime: '02:00',
        schedule: { weekly: { dayOfWeek: 'Sunday', intervalWeeks: 1 } } }
    }))
  };
}

export function demoEvidence(platform = 'cloud', scope = defaultScope()) {
  const raw = demoRaw(platform);
  const evidence = {
    schemaVersion: '1.0', toolVersion, catalogVersion, catalogDigest, collectedAt: demoTimestamp, synthetic: true,
    target: { platform, context: `demo-${platform}`, subscription: '00000000-0000-0000-0000-000000000001',
      resourceGroup: 'rg-xray-demo', cluster: 'xray-demo' },
    scope, sources: {}
  };
  for (const id of requiredSources(scope, platform)) {
    evidence.sources[id] = activeSources.includes(id)
      ? { status: 'notCollected', collectedAt: demoTimestamp, reason: 'Synthetic demo; no active tests executed.' }
      : { status: 'ok', collectedAt: demoTimestamp, durationMs: 0, commands: [],
        data: scopeProjection(id, projectSource(id, raw[id], platform), scope) };
  }
  return evidence;
}
