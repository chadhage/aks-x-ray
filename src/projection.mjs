export const workloadSources = ['deployments', 'statefulsets', 'daemonsets', 'jobs', 'cronjobs', 'pods'];
export const namespacedSources = new Set([
  ...workloadSources, 'services', 'endpointslices', 'ingresses', 'networkpolicies',
  'pdbs', 'pvcs', 'hpas', 'serviceaccounts', 'resourcequotas', 'limitranges', 'events'
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
  clusterrolebindings: 'clusterrolebindings.rbac.authorization.k8s.io'
};
export const activeSources = ['activeConnectivity', 'activeE2E', 'activeLoad', 'activeSecurity'];
export const sourceIds = [
  'context', 'cluster', 'nodepools', 'diagnostics', 'maintenance',
  ...Object.keys(kubernetesResources), ...activeSources
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
    identity: pick(raw.identity ?? p.identity, ['type']),
    apiServerAccessProfile: pick(p.apiServerAccessProfile, ['enablePrivateCluster', 'authorizedIpRanges', 'authorizedIPRanges']),
    networkProfile: pick(p.networkProfile, ['networkPlugin', 'networkPluginMode', 'networkPolicy', 'networkDataplane',
      'podCidr', 'podCidrs', 'serviceCidr', 'serviceCidrs', 'dnsServiceIP', 'outboundType', 'loadBalancerSku']),
    oidcIssuerProfile: pick(p.oidcIssuerProfile, ['enabled']),
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
    case 'serviceaccounts': return { ...base, automountServiceAccountToken: raw.automountServiceAccountToken };
    case 'resourcequotas': return { ...base, hard: spec.hard };
    case 'limitranges': return { ...base, limits: spec.limits };
    case 'events':
      return { ...base, type: raw.type, reason: raw.reason, count: raw.count,
        lastTimestamp: raw.lastTimestamp ?? raw.eventTime,
        involvedObject: pick(raw.involvedObject, ['kind', 'name', 'namespace']) };
    case 'clusterrolebindings':
      return { ...base, roleRef: pick(raw.roleRef, ['kind', 'name', 'apiGroup']),
        subjects: raw.subjects?.map((s) => pick(s, ['kind', 'name', 'namespace'])) };
    default: throw new Error(`Missing projection for ${id}`);
  }
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
