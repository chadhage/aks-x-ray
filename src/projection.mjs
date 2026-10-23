export const workloadSources = ['deployments', 'statefulsets', 'daemonsets', 'jobs', 'cronjobs', 'pods'];
export const namespacedSources = new Set([
  ...workloadSources, 'services', 'endpointslices', 'ingresses', 'networkpolicies',
  'pdbs', 'pvcs', 'hpas', 'serviceaccounts', 'resourcequotas', 'limitranges', 'events', 'roles', 'rolebindings'
]);
export const kubernetesResources = {
  nodes: 'nodes', namespaces: 'namespaces', deployments: 'deployments.apps',
  statefulsets: 'statefulsets.apps', daemonsets: 'daemonsets.apps', jobs: 'jobs.batch',
  cronjobs: 'cronjobs.batch', pods: 'pods', services: 'services',
  endpointslices: 'endpointslices.discovery.k8s.io', ingresses: 'ingresses.networking.k8s.io',
  networkpolicies: 'networkpolicies.networking.k8s.io', pdbs: 'poddisruptionbudgets.policy',
  pvcs: 'persistentvolumeclaims', pvs: 'persistentvolumes', storageclasses: 'storageclasses.storage.k8s.io',
  hpas: 'horizontalpodautoscalers.autoscaling', serviceaccounts: 'serviceaccounts',
  resourcequotas: 'resourcequotas', limitranges: 'limitranges', events: 'events',
  clusterrolebindings: 'clusterrolebindings.rbac.authorization.k8s.io',
  roles: 'roles.rbac.authorization.k8s.io', rolebindings: 'rolebindings.rbac.authorization.k8s.io',
  clusterroles: 'clusterroles.rbac.authorization.k8s.io',
  validatingwebhooks: 'validatingwebhookconfigurations.admissionregistration.k8s.io',
  mutatingwebhooks: 'mutatingwebhookconfigurations.admissionregistration.k8s.io'
};
export const supplementalSources = ['accounts', 'roleAssignments', 'policyStates', 'defenderPricing',
  'defenderAssessments', 'advisorRecommendations', 'relatedResources', 'roleDefinitions', 'federatedCredentials', 'resourceGraph'];
export const activeSources = ['activeConnectivity', 'activeE2E', 'activeLoad', 'activeSecurity'];
export const sourceIds = [
  'context', 'cluster', 'nodepools', 'diagnostics', 'maintenance',
  ...Object.keys(kubernetesResources), ...supplementalSources, ...activeSources
];

export function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function pick(object, keys) {
  if (!isObject(object)) return undefined;
  return Object.fromEntries(keys.filter((key) => object[key] !== undefined).map((key) => [key, object[key]]));
}

function list(raw) {
  if (Array.isArray(raw)) return raw;
  if (Array.isArray(raw?.items)) return raw.items;
  if (Array.isArray(raw?.value)) return raw.value;
  if (isObject(raw?.metadata) && typeof raw.metadata.name === 'string') return [raw];
  throw new Error('Expected an explicit resource list; missing items cannot be treated as an empty list.');
}

function metadata(raw) {
  if (!isObject(raw?.metadata) || typeof raw.metadata.name !== 'string') {
    throw new Error('Resource metadata.name is missing.');
  }
  return {
    ...pick(raw.metadata, ['name', 'namespace', 'uid', 'generation', 'labels']),
    ownerReferences: raw.metadata.ownerReferences?.map((owner) => pick(owner, ['kind', 'name']))
  };
}

function securityContext(value) {
  if (!isObject(value)) return undefined;
  return {
    ...pick(value, ['privileged', 'allowPrivilegeEscalation', 'runAsNonRoot', 'runAsUser', 'readOnlyRootFilesystem']),
    capabilities: pick(value.capabilities, ['add', 'drop']),
    seccompProfile: pick(value.seccompProfile, ['type']),
    windowsOptions: pick(value.windowsOptions, ['hostProcess'])
  };
}

function container(value) {
  return {
    ...pick(value, ['name', 'image']),
    resources: {
      requests: pick(value.resources?.requests, ['cpu', 'memory']),
      limits: pick(value.resources?.limits, ['cpu', 'memory'])
    },
    securityContext: securityContext(value.securityContext),
    probes: {
      readiness: isObject(value.readinessProbe),
      liveness: isObject(value.livenessProbe),
      startup: isObject(value.startupProbe)
    }
  };
}

function podSpec(value) {
  if (!isObject(value) || !Array.isArray(value.containers)) throw new Error('Pod specification is incomplete.');
  return {
    ...pick(value, ['nodeName', 'nodeSelector', 'restartPolicy', 'hostNetwork', 'hostPID', 'hostIPC',
      'hostUsers', 'serviceAccountName', 'automountServiceAccountToken', 'topologySpreadConstraints']),
    osName: value.os?.name,
    securityContext: securityContext(value.securityContext),
    podAntiAffinity: value.affinity?.podAntiAffinity,
    containers: value.containers.map(container),
    initContainers: value.initContainers?.map(container),
    ephemeralContainers: value.ephemeralContainers?.map(container),
    volumes: value.volumes?.map((volume) => ({
      name: volume.name,
      type: volume.hostPath ? 'hostPath' : volume.persistentVolumeClaim ? 'persistentVolumeClaim'
        : volume.secret ? 'secret' : volume.csi ? 'csi' : 'other'
    }))
  };
}

function workload(raw) {
  const template = raw.kind === 'Pod' ? raw : raw.kind === 'CronJob'
    ? raw.spec?.jobTemplate?.spec?.template : raw.spec?.template;
  const m = metadata(raw);
  return {
    kind: raw.kind, metadata: m,
    replicas: raw.kind === 'Deployment' || raw.kind === 'StatefulSet' ? (raw.spec?.replicas ?? 1) : undefined,
    observedGeneration: raw.status?.observedGeneration,
    availableReplicas: raw.status?.availableReplicas,
    pod: { labels: template?.metadata?.labels ?? {}, spec: podSpec(template?.spec) },
    phase: raw.status?.phase,
    containerStatuses: raw.status?.containerStatuses?.map((status) => ({
      ...pick(status, ['name', 'ready', 'restartCount']),
      waitingReason: status.state?.waiting?.reason,
      terminatedReason: status.state?.terminated?.reason,
      exitCode: status.state?.terminated?.exitCode
    }))
  };
}

function armIdentity(value) {
  if (!isObject(value)) return undefined;
  return { ...pick(value, ['type', 'principalId', 'tenantId']),
    ...(isObject(value.userAssignedIdentities) ? { userAssignedIdentities: Object.fromEntries(
      Object.entries(value.userAssignedIdentities).map(([id, identity]) => [id, pick(identity, ['principalId', 'clientId']) ?? {}])
    ) } : {}) };
}

function issuer(value) {
  if (value === undefined) return undefined;
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error('Issuer must be HTTPS without credentials or query parameters.');
  return value;
}

function cluster(raw, platform) {
  if (!isObject(raw)) throw new Error('Expected ARM cluster metadata.');
  if (typeof raw.name !== 'string' || typeof raw.id !== 'string') throw new Error('ARM cluster name and resource ID are required.');
  const p = isObject(raw.properties) ? raw.properties : raw;
  if (platform === 'local') {
    return {
      ...pick(raw, ['id', 'name', 'type', 'location']),
      ...pick(p, ['provisioningState', 'kubernetesVersion']),
      controlPlane: {
        count: p.controlPlane?.count,
        controlPlaneEndpoint: pick(p.controlPlane?.controlPlaneEndpoint, ['hostIP'])
      }
    };
  }
  return {
    ...pick(raw, ['id', 'name', 'type', 'location']),
    ...pick(p, ['kubernetesVersion', 'currentKubernetesVersion', 'fqdn', 'privateFqdn', 'disableLocalAccounts']),
    enableRBAC: p.enableRBAC ?? p.enableRbac,
    sku: pick(raw.sku ?? p.sku, ['name', 'tier']),
    aadProfile: pick(p.aadProfile, ['managed', 'enableAzureRbac', 'enableAzureRBAC']),
    identity: armIdentity(raw.identity ?? p.identity),
    identityProfile: { kubeletidentity: pick(p.identityProfile?.kubeletidentity ?? p.identityProfile?.kubeletIdentity, ['resourceId', 'objectId', 'clientId']) },
    nodeResourceGroup: p.nodeResourceGroup,
    linkedResourceIds: [...new Set([
      p.diskEncryptionSetId ?? p.diskEncryptionSetID, p.apiServerAccessProfile?.subnetId,
      ...Object.keys((raw.identity ?? p.identity)?.userAssignedIdentities ?? {}),
      p.identityProfile?.kubeletidentity?.resourceId ?? p.identityProfile?.kubeletIdentity?.resourceId,
      ...(p.agentPoolProfiles ?? []).flatMap((pool) => [pool.vnetSubnetId ?? pool.vnetSubnetID, pool.podSubnetId ?? pool.podSubnetID]),
      p.addonProfiles?.omsagent?.config?.logAnalyticsWorkspaceResourceID,
      ...(p.networkProfile?.loadBalancerProfile?.effectiveOutboundIPs ?? p.networkProfile?.loadBalancerProfile?.effectiveOutboundIps ?? []).map((value) => value.id),
      ...(p.networkProfile?.natGatewayProfile?.effectiveOutboundIPs ?? p.networkProfile?.natGatewayProfile?.effectiveOutboundIps ?? []).map((value) => value.id)
    ].filter((value) => typeof value === 'string' && value.length))],
    apiServerAccessProfile: pick(p.apiServerAccessProfile, ['enablePrivateCluster', 'authorizedIpRanges', 'authorizedIPRanges']),
    networkProfile: pick(p.networkProfile, ['networkPlugin', 'networkPluginMode', 'networkPolicy', 'networkDataplane',
      'podCidr', 'podCidrs', 'serviceCidr', 'serviceCidrs', 'dnsServiceIP', 'outboundType', 'loadBalancerSku']),
    oidcIssuerProfile: { ...pick(p.oidcIssuerProfile, ['enabled']), issuerUrl: issuer(p.oidcIssuerProfile?.issuerUrl ?? p.oidcIssuerProfile?.issuerURL) },
    securityProfile: {
      workloadIdentity: pick(p.securityProfile?.workloadIdentity, ['enabled']),
      defender: { securityMonitoring: pick(p.securityProfile?.defender?.securityMonitoring, ['enabled']) }
    },
    azureMonitorProfile: { metrics: pick(p.azureMonitorProfile?.metrics, ['enabled']) },
    addonProfiles: p.addonProfiles ? Object.fromEntries(
      ['azurepolicy', 'omsagent', 'azureKeyvaultSecretsProvider'].filter((key) => p.addonProfiles[key] !== undefined)
        .map((key) => [key, { enabled: p.addonProfiles[key].enabled }])
    ) : undefined,
    autoUpgradeProfile: pick(p.autoUpgradeProfile, ['upgradeChannel', 'nodeOsUpgradeChannel', 'nodeOSUpgradeChannel']),
    nodeProvisioningProfile: pick(p.nodeProvisioningProfile, ['mode'])
  };
}

export function projectSource(id, raw, platform = 'cloud') {
  let data;
  if (id === 'cluster') data = cluster(raw, platform);
  else if (id === 'context') {
    const server = new URL(String(raw).trim());
    if (server.protocol !== 'https:' || server.username || server.password || server.search || server.hash) {
      throw new Error('The kubeconfig server must be an HTTPS endpoint without credentials or query parameters.');
    }
    data = { server: server.origin + (server.pathname === '/' ? '' : server.pathname) };
  } else if (id === 'accounts') {
    if (!isObject(raw)) throw new Error('Expected account metadata.');
    data = { items: [pick(raw, ['id', 'tenantId', 'state'])] };
  } else if (id === 'defenderPricing') {
    if (!isObject(raw)) throw new Error('Expected Defender plan metadata.');
    data = { items: [{ ...pick(raw, ['name', 'pricingTier', 'subPlan']),
      extensions: raw.extensions?.map((extension) => pick(extension, ['name', 'isEnabled'])) }] };
  } else if (id === 'roleAssignments') {
    data = { items: list(raw).map((value) => {
      const p = value.properties ?? value;
      return { ...pick(value, ['id', 'name']), ...pick(p, ['scope', 'roleDefinitionId', 'principalId', 'principalType', 'conditionVersion']),
        hasCondition: typeof p.condition === 'string' ? p.condition.trim().length > 0
          : p.condition == null && p.conditionVersion == null ? false : null };
    }) };
  } else if (id === 'roleDefinitions') {
    data = { items: list(raw).map((value) => {
      const p = value.properties ?? value;
      return { ...pick(value, ['id', 'name']), ...pick(p, ['roleName', 'roleType', 'assignableScopes']),
        permissions: p.permissions?.map((permission) => pick(permission, ['actions', 'notActions', 'dataActions', 'notDataActions'])) };
    }) };
  } else if (id === 'federatedCredentials') {
    data = { items: list(raw).map((value) => {
      const p = value.properties ?? value;
      return { ...pick(value, ['id', 'name']), ...pick(p, ['subject', 'audiences']), issuer: issuer(p.issuer) };
    }) };
  } else if (id === 'resourceGraph') {
    data = { items: (Array.isArray(raw?.data) ? raw.data : list(raw)).map(projectArmResource) };
  } else if (id === 'policyStates') {
    data = { items: list(raw).map((value) => pick(value, ['resourceId', 'complianceState', 'timestamp',
      'policyAssignmentId', 'policyDefinitionId', 'policyDefinitionReferenceId'])) };
  } else if (id === 'defenderAssessments') {
    data = { items: list(raw).map((value) => {
      const p = value.properties ?? value;
      return { ...pick(value, ['id', 'name']), ...pick(p, ['displayName']),
        status: pick(p.status, ['code']), resourceId: p.resourceDetails?.id ?? p.resourceDetails?.Id };
    }) };
  } else if (id === 'advisorRecommendations') {
    data = { items: list(raw).map((value) => {
      const p = value.properties ?? value;
      return { ...pick(value, ['id', 'name']), ...pick(p, ['category', 'impact', 'recommendationTypeId']),
        resourceId: p.resourceMetadata?.resourceId };
    }) };
  } else if (id === 'relatedResources') {
    data = { items: (Array.isArray(raw) ? raw : [raw]).map(projectArmResource) };
  } else if (id === 'nodepools') {
    data = { items: list(raw).map((pool) => pick(pool, [
      'name', 'mode', 'count', 'vmSize', 'osType', 'osSKU', 'osSku', 'nodeTaints',
      'availabilityZones', 'enableAutoScaling', 'minCount', 'maxCount', 'orchestratorVersion', 'nodeImageVersion'
    ])) };
  } else if (id === 'diagnostics') {
    data = { items: list(raw).map((setting) => ({
      ...pick(setting, ['name', 'workspaceId', 'storageAccountId', 'eventHubAuthorizationRuleId', 'marketplacePartnerId']),
      logs: setting.logs?.map((log) => pick(log, ['category', 'categoryGroup', 'enabled']))
    })) };
  } else if (id === 'maintenance') {
    data = { items: list(raw).map((setting) => ({
      name: setting.name,
      maintenanceWindow: pick(setting.maintenanceWindow ?? setting.properties?.maintenanceWindow,
        ['durationHours', 'schedule', 'utcOffset', 'startDate', 'startTime', 'notAllowedDates'])
    })) };
  } else if (workloadSources.includes(id)) {
    data = { items: list(raw).map(workload) };
  } else if (id in kubernetesResources) {
    data = { items: list(raw).map((resource) => projectResource(id, resource)) };
  } else throw new Error(`Unsupported collector projection: ${id}`);
  return JSON.parse(JSON.stringify(data));
}

function projectResource(id, raw) {
  const base = { kind: raw.kind, metadata: metadata(raw) };
  const spec = raw.spec ?? {};
  switch (id) {
    case 'nodes':
      return { ...base, conditions: raw.status?.conditions?.map((c) => pick(c, ['type', 'status', 'reason'])),
        nodeInfo: pick(raw.status?.nodeInfo, ['operatingSystem', 'osImage', 'kubeletVersion', 'containerRuntimeVersion']),
        allocatable: pick(raw.status?.allocatable, ['cpu', 'memory', 'pods']), taints: spec.taints };
    case 'namespaces': return base;
    case 'services':
      return { ...base, ...pick(spec, ['type', 'clusterIP', 'selector', 'externalIPs']),
        internal: raw.metadata.annotations?.['service.beta.kubernetes.io/azure-load-balancer-internal'],
        ports: spec.ports?.map((port) => pick(port, ['port', 'targetPort', 'protocol'])),
        loadBalancerIngress: raw.status?.loadBalancer?.ingress?.map((entry) => pick(entry, ['ip', 'hostname'])) };
    case 'endpointslices':
      return { ...base, serviceName: raw.metadata.labels?.['kubernetes.io/service-name'],
        endpoints: raw.endpoints?.map((endpoint) => ({
          addresses: endpoint.addresses, ready: endpoint.conditions?.ready
        })) };
    case 'ingresses':
      return { ...base, hosts: spec.rules?.map((rule) => rule.host),
        tls: spec.tls?.map((entry) => ({ hosts: entry.hosts })) };
    case 'networkpolicies':
      return { ...base, spec: pick(spec, ['podSelector', 'policyTypes', 'ingress', 'egress']) };
    case 'pdbs':
      return { ...base, spec: pick(spec, ['selector', 'minAvailable', 'maxUnavailable']),
        status: pick(raw.status, ['disruptionsAllowed', 'expectedPods', 'currentHealthy', 'desiredHealthy']) };
    case 'pvcs':
      return { ...base, ...pick(spec, ['storageClassName', 'volumeName', 'accessModes']),
        phase: raw.status?.phase, storageRequest: spec.resources?.requests?.storage };
    case 'pvs':
      return { ...base, ...pick(spec, ['storageClassName', 'persistentVolumeReclaimPolicy', 'accessModes']),
        claimRef: pick(spec.claimRef, ['namespace', 'name']), csiDriver: spec.csi?.driver };
    case 'storageclasses':
      return { ...base, ...pick(raw, ['provisioner', 'volumeBindingMode', 'allowVolumeExpansion', 'reclaimPolicy']) };
    case 'hpas':
      return { ...base, minReplicas: spec.minReplicas ?? 1, maxReplicas: spec.maxReplicas,
        scaleTargetRef: pick(spec.scaleTargetRef, ['kind', 'name']),
        conditions: raw.status?.conditions?.map((c) => pick(c, ['type', 'status', 'reason'])) };
    case 'serviceaccounts': return { ...base, automountServiceAccountToken: raw.automountServiceAccountToken,
      workloadIdentity: { clientId: raw.metadata.annotations?.['azure.workload.identity/client-id'],
        tenantId: raw.metadata.annotations?.['azure.workload.identity/tenant-id'] } };
    case 'resourcequotas': return { ...base, hard: spec.hard };
    case 'limitranges': return { ...base, limits: spec.limits };
    case 'events':
      return { ...base, type: raw.type, reason: raw.reason, count: raw.count,
        lastTimestamp: raw.lastTimestamp ?? raw.eventTime,
        involvedObject: pick(raw.involvedObject, ['kind', 'name', 'namespace']) };
    case 'roles':
    case 'clusterroles':
      return { ...base, rules: raw.rules?.map((rule) => pick(rule, ['apiGroups', 'resources', 'verbs', 'resourceNames', 'nonResourceURLs'])) };
    case 'validatingwebhooks':
    case 'mutatingwebhooks':
      return { ...base, webhooks: raw.webhooks?.map((webhook) => ({
        ...pick(webhook, ['name', 'failurePolicy', 'timeoutSeconds', 'sideEffects', 'matchPolicy', 'namespaceSelector', 'objectSelector']),
        rules: webhook.rules?.map((rule) => pick(rule, ['apiGroups', 'apiVersions', 'resources', 'operations', 'scope'])),
        service: pick(webhook.clientConfig?.service, ['name', 'namespace', 'port'])
      })) };
    case 'rolebindings':
    case 'clusterrolebindings':
      return { ...base, roleRef: pick(raw.roleRef, ['kind', 'name', 'apiGroup']),
        subjects: raw.subjects?.map((s) => pick(s, ['kind', 'name', 'namespace'])) };
    default: throw new Error(`Missing projection for ${id}`);
  }
}

function projectArmResource(raw) {
  if (!isObject(raw) || typeof raw.id !== 'string' || typeof raw.type !== 'string' || typeof raw.name !== 'string') {
    throw new Error('Related resource metadata requires an explicit resource ID, type and name.');
  }
  const p = raw.properties ?? raw;
  const type = raw.type.toLowerCase();
  let configuration;
  let links = [];
  if (type === 'microsoft.containerregistry/registries') {
    configuration = { ...pick(p, ['adminUserEnabled', 'publicNetworkAccess', 'zoneRedundancy', 'dataEndpointEnabled']),
      networkRuleSet: pick(p.networkRuleSet, ['defaultAction']), policies: {
        trustPolicy: pick(p.policies?.trustPolicy, ['status']), quarantinePolicy: pick(p.policies?.quarantinePolicy, ['status']),
        retentionPolicy: pick(p.policies?.retentionPolicy, ['status', 'days'])
      } };
  } else if (type === 'microsoft.keyvault/vaults') {
    configuration = { ...pick(p, ['enableRbacAuthorization', 'enableSoftDelete', 'enablePurgeProtection',
      'softDeleteRetentionInDays', 'publicNetworkAccess']), networkAcls: pick(p.networkAcls, ['defaultAction', 'bypass']) };
  } else if (type === 'microsoft.storage/storageaccounts') {
    configuration = { ...pick(p, ['supportsHttpsTrafficOnly', 'minimumTlsVersion', 'allowBlobPublicAccess',
      'allowSharedKeyAccess', 'publicNetworkAccess']), networkAcls: pick(p.networkAcls, ['defaultAction', 'bypass']),
    encryption: pick(p.encryption, ['keySource', 'requireInfrastructureEncryption']) };
  } else if (type === 'microsoft.network/virtualnetworks/subnets') {
    configuration = { ...pick(p, ['addressPrefix', 'addressPrefixes', 'privateEndpointNetworkPolicies', 'privateLinkServiceNetworkPolicies']),
      networkSecurityGroupId: p.networkSecurityGroup?.id, routeTableId: p.routeTable?.id,
      natGatewayId: p.natGateway?.id, serviceEndpoints: p.serviceEndpoints?.map((endpoint) => pick(endpoint, ['service', 'locations'])) };
    links = [p.networkSecurityGroup?.id, p.routeTable?.id, p.natGateway?.id];
  } else if (type === 'microsoft.network/networksecuritygroups') {
    configuration = { securityRules: p.securityRules?.map((rule) => ({
      name: rule.name, ...pick(rule.properties ?? rule, ['priority', 'direction', 'access', 'protocol',
        'sourceAddressPrefix', 'sourceAddressPrefixes', 'destinationAddressPrefix', 'destinationAddressPrefixes',
        'sourcePortRange', 'sourcePortRanges', 'destinationPortRange', 'destinationPortRanges'])
    })) };
  } else if (type === 'microsoft.network/routetables') {
    configuration = { disableBgpRoutePropagation: p.disableBgpRoutePropagation,
      routes: p.routes?.map((route) => ({ name: route.name, ...pick(route.properties ?? route, ['addressPrefix', 'nextHopType', 'nextHopIpAddress']) })) };
  } else if (type === 'microsoft.network/publicipaddresses') {
    configuration = { ...pick(p, ['publicIPAllocationMethod', 'publicIPAddressVersion', 'ipAddress', 'idleTimeoutInMinutes']), sku: pick(raw.sku, ['name', 'tier']) };
  } else if (type === 'microsoft.operationalinsights/workspaces') {
    configuration = pick(p, ['retentionInDays', 'publicNetworkAccessForIngestion', 'publicNetworkAccessForQuery']);
  } else if (type === 'microsoft.compute/diskencryptionsets') {
    configuration = pick(p, ['encryptionType', 'rotationToLatestKeyVersionEnabled']);
  } else if (type === 'microsoft.managedidentity/userassignedidentities') {
    configuration = pick(p, ['principalId', 'clientId', 'tenantId']);
  }
  links.push(...Object.keys(raw.identity?.userAssignedIdentities ?? {}));
  return { ...pick(raw, ['id', 'name', 'type', 'location', 'subscriptionId', 'resourceGroup']), identity: armIdentity(raw.identity), configuration: configuration ?? {},
    supported: configuration !== undefined,
    linkedResourceIds: links.filter((id) => typeof id === 'string' && id.length) };
}

export function inScope(namespace, scope) {
  return !scope.excludedNamespaces.includes(namespace)
    && (scope.namespaces === null || scope.namespaces.includes(namespace));
}

export function scopeProjection(id, data, scope) {
  if (namespacedSources.has(id)) {
    return { items: data.items.filter((item) => inScope(item.metadata.namespace, scope)) };
  }
  if (id === 'namespaces') {
    return { items: data.items.filter((item) => inScope(item.metadata.name, scope)) };
  }
  return data;
}
