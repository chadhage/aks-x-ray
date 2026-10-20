import { binding } from './collector.mjs';
import { inScope, workloadSources } from './projection.mjs';
import { cidr, compareQuantities, contains, matchesSelector, overlaps, percentile, quantity } from './quantities.mjs';

const outcome = (status, message, observed = {}) => ({ status, message, observed });
const ref = (item) => `${item.kind ?? 'Resource'}/${item.metadata?.namespace ? `${item.metadata.namespace}/` : ''}${item.metadata?.name ?? item.name}`;
const items = (evidence, id) => evidence.sources[id].data.items;
const scoped = (evidence, id) => items(evidence, id).filter((item) => inScope(item.metadata.namespace, evidence.scope));
const workloads = (evidence) => workloadSources.flatMap((id) => scoped(evidence, id));
const services = (evidence) => ['deployments', 'statefulsets'].flatMap((id) => scoped(evidence, id)).filter((w) => w.replicas > 0);
const activeNamespaces = (evidence) => [...new Set(workloads(evidence).map((w) => w.metadata.namespace))];
const observedList = (values) => ({ count: values.length, examples: values.slice(0, 20), omitted: Math.max(0, values.length - 20) });
const automatic = (evidence) => evidence.sources.cluster?.data?.sku?.name?.toLowerCase() === 'automatic';

export function checkAll(values, predicate, description, empty = 'No applicable resources were observed.') {
  if (!values.length) return outcome('notApplicable', empty);
  const failed = [];
  const unknown = [];
  for (const value of values) {
    const valid = predicate(value);
    if (valid === false) failed.push(typeof value === 'string' ? value : ref(value));
    else if (valid !== true) unknown.push(typeof value === 'string' ? value : ref(value));
  }
  const status = failed.length ? 'fail' : unknown.length ? 'unknown' : 'pass';
  return {
    ...outcome(status, `${description} Checked ${values.length}; deviations ${failed.length}; unknown ${unknown.length}.`,
      { checked: values.length, deviations: observedList(failed), unknown: observedList(unknown) }),
    incomplete: unknown.length > 0
  };
}

function flag(value, description) {
  if (typeof value !== 'boolean') return outcome('unknown', `${description} The API field was not explicitly observed.`);
  return outcome(value ? 'pass' : 'fail', `${description} Observed: ${value}.`, { value });
}

function containerEntries(evidence, { linux = false, ephemeral = true, init = true, longRunning = false } = {}) {
  const all = workloads(evidence);
  const nodes = evidence.sources.nodes?.status === 'ok' ? items(evidence, 'nodes') : [];
  const podOS = (workload) => {
    const spec = workload.pod.spec;
    const explicit = spec.osName ?? spec.nodeSelector?.['kubernetes.io/os'];
    if (explicit) return explicit;
    return nodes.find((node) => node.metadata.name === spec.nodeName)?.nodeInfo?.operatingSystem;
  };
  return all.filter((workload) => !longRunning || !['Job', 'CronJob'].includes(workload.kind)
    && !['Never', 'OnFailure'].includes(workload.pod.spec.restartPolicy)
    && !(workload.metadata.ownerReferences ?? []).some((owner) => owner.kind === 'Job'))
    .flatMap((workload) => {
      const spec = workload.pod.spec;
      let os = podOS(workload);
      if (!os && workload.kind !== 'Pod' && Object.keys(workload.pod.labels).length) {
        const observed = all.filter((pod) => pod.kind === 'Pod' && pod.metadata.namespace === workload.metadata.namespace
          && Object.entries(workload.pod.labels).every(([key, value]) => pod.pod.labels[key] === value));
        const candidates = [...new Set(observed.map(podOS).filter(Boolean))];
        if (candidates.length === 1) os = candidates[0];
      }
      if (linux && os === 'windows') return [];
      return [...spec.containers, ...(init ? spec.initContainers ?? [] : []), ...(ephemeral ? spec.ephemeralContainers ?? [] : [])]
        .map((container) => ({
          ...workload, container, spec, os,
          metadata: { ...workload.metadata, name: `${workload.metadata.name}/${container.name}` }
        }));
    });
}

function linuxCheck(evidence, predicate, description) {
  return checkAll(containerEntries(evidence, { linux: true }),
    (entry) => entry.os === 'linux' ? predicate(entry) : null, description,
    'No applicable Linux containers were observed. Windows is not evaluated using Linux controls.');
}

function resourceCheck(evidence, group) {
  return checkAll(containerEntries(evidence, { ephemeral: false }), ({ container }) => {
    const cpu = quantity(container.resources?.[group]?.cpu);
    const memory = quantity(container.resources?.[group]?.memory);
    return cpu !== null && memory !== null && cpu > 0 && memory > 0;
  }, `Positive CPU and memory ${group} declarations.`);
}

function namespaceCheck(evidence, predicate, description) {
  return checkAll(activeNamespaces(evidence), predicate, description, 'No selected workload namespaces were observed.');
}

function pbdCount(value, total) {
  if (Number.isInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^\d+%$/.test(value)) {
    const percent = Number(value.slice(0, -1));
    if (percent <= 100) return Math.ceil(total * percent / 100);
  }
  throw new Error('PDB availability must be a nonnegative integer or a percentage from 0% to 100%.');
}

export function loadStatistics(data) {
  const { limits, budgets, samples, durationMs } = data;
  if (!limits || !budgets || !Array.isArray(samples) || !samples.length
    || !Number.isFinite(durationMs) || durationMs < 0
    || !Number.isInteger(limits.requests) || limits.requests < 1 || limits.requests > 200
    || !Number.isInteger(limits.concurrency) || limits.concurrency < 1 || limits.concurrency > 4
    || !Number.isFinite(limits.durationSeconds) || limits.durationSeconds < 1 || limits.durationSeconds > 30
    || !Number.isFinite(limits.workerPacingMs) || limits.workerPacingMs < 100
    || samples.length > limits.requests || durationMs > limits.durationSeconds * 1000 + 1000
    || !Number.isFinite(budgets.p95Ms) || budgets.p95Ms <= 0
    || !Number.isFinite(budgets.maxErrorRatePercent) || budgets.maxErrorRatePercent < 0 || budgets.maxErrorRatePercent > 100
    || samples.some((sample) => typeof sample.ok !== 'boolean' || !Number.isFinite(sample.latencyMs) || sample.latencyMs < 0)) {
    throw new Error('Invalid or out-of-safety-bounds load evidence.');
  }
  const failed = samples.filter((sample) => !sample.ok).length;
  const p95Ms = percentile(samples.map((sample) => sample.latencyMs));
  const errorRatePercent = failed / samples.length * 100;
  return {
    attempted: samples.length, successes: samples.length - failed, failed, p95Ms, errorRatePercent, durationMs,
    limits, budgets, withinBudgets: p95Ms <= budgets.p95Ms && errorRatePercent <= budgets.maxErrorRatePercent
  };
}

export function evaluateRule(id, evidence) {
  const cluster = evidence.sources.cluster?.data;
  switch (id) {
    case 'CP-001': {
      const value = binding(evidence);
      return outcome(value.status === 'verified' ? 'pass' : value.status === 'mismatch' ? 'fail' : 'unknown', value.message, value);
    }
    case 'CP-002': {
      const profile = cluster.apiServerAccessProfile;
      if (profile?.enablePrivateCluster === true) return outcome('pass', 'Private API-server configuration is explicitly enabled.');
      const ranges = profile?.authorizedIpRanges ?? profile?.authorizedIPRanges;
      if (!Array.isArray(ranges)) return outcome('unknown', 'Neither private enablement nor a complete authorized-IP list was observed.');
      const restricted = ranges.length > 0 && ranges.every((range) => cidr(range).prefix > 0);
      return outcome(restricted ? 'pass' : 'fail', 'Public API authorized-IP configuration was evaluated; effective reachability is not established.', { ranges });
    }
    case 'CP-003':
      if (!cluster.sku?.tier) return outcome('unknown', 'Cloud service tier was not observed.');
      return outcome(['standard', 'premium'].includes(cluster.sku.tier.toLowerCase()) ? 'pass' : 'fail',
        'Production control-plane tier declaration.', { tier: cluster.sku.tier });
    case 'ID-001': return flag(cluster.enableRBAC, 'Kubernetes RBAC enablement.');
    case 'ID-002': return flag(cluster.aadProfile?.managed, 'Managed Entra integration.');
    case 'ID-003': return flag(cluster.disableLocalAccounts, 'Local account disablement.');
    case 'ID-004': {
      const workloadIdentity = cluster.securityProfile?.workloadIdentity?.enabled;
      const oidc = cluster.oidcIssuerProfile?.enabled;
      if (typeof workloadIdentity !== 'boolean' || typeof oidc !== 'boolean') {
        return outcome('unknown', 'Workload identity and OIDC fields must both be explicitly observed.', { workloadIdentity, oidc });
      }
      return outcome(workloadIdentity && oidc ? 'pass' : workloadIdentity && !oidc ? 'fail' : 'review',
        workloadIdentity && oidc ? 'Workload identity and OIDC capabilities are configured; federation is not verified.'
          : workloadIdentity ? 'Workload identity is enabled without OIDC.' : 'Workload identity is disabled; review workload authentication needs.',
        { workloadIdentity, oidc });
    }
    case 'ID-006':
      return checkAll(workloads(evidence), (workload) => Boolean(workload.pod.spec.serviceAccountName
        && workload.pod.spec.serviceAccountName !== 'default'), 'Dedicated workload service-account declarations.');
    case 'ND-001':
      if (!items(evidence, 'nodes').length) return outcome('fail', 'The API returned zero nodes; readiness cannot be established.');
      return checkAll(items(evidence, 'nodes'), (node) => {
        const ready = node.conditions?.find((condition) => condition.type === 'Ready')?.status;
        return ready === undefined || ready === 'Unknown' ? null : ready === 'True';
      }, 'Node readiness.');
    case 'ND-002':
      if (!items(evidence, 'nodes').length) return outcome('unknown', 'No node pressure conditions were available.');
      return checkAll(items(evidence, 'nodes'), (node) => {
        const values = ['MemoryPressure', 'DiskPressure', 'PIDPressure']
          .map((type) => node.conditions?.find((condition) => condition.type === type)?.status);
        return values.includes('True') ? false : values.every((value) => value === 'False') ? true : null;
      }, 'Explicit node pressure conditions.');
    case 'ND-003':
    case 'ND-004': {
      if (automatic(evidence)) return outcome('review', 'AKS Automatic manages system capacity; operator-pool heuristics are not applied.');
      const pools = items(evidence, 'nodepools').filter((pool) => pool.mode === 'System');
      if (!pools.length) return outcome('fail', 'No explicit System node pool was observed.');
      return checkAll(pools, id === 'ND-003'
        ? (pool) => typeof pool.count === 'number' ? pool.count >= 2 : null
        : (pool) => Array.isArray(pool.nodeTaints) ? pool.nodeTaints.includes('CriticalAddonsOnly=true:NoSchedule') : null,
      id === 'ND-003' ? 'System-pool redundant capacity.' : 'System-pool taint declarations.');
    }
    case 'NET-001': {
      const profile = cluster.networkProfile;
      if (!profile) return outcome('unknown', 'Network profile was not observed.');
      if (profile.networkDataplane === 'cilium') return outcome('pass', 'Cilium dataplane is configured; enforcement is not tested.');
      if (typeof profile.networkPolicy !== 'string') return outcome('unknown', 'Network-policy engine field was not observed.');
      return outcome(profile.networkPolicy && profile.networkPolicy !== 'none' ? 'pass' : 'fail',
        'Network-policy engine configuration.', { networkPolicy: profile.networkPolicy, networkDataplane: profile.networkDataplane });
    }
    case 'NET-002': {
      const policies = scoped(evidence, 'networkpolicies');
      return namespaceCheck(evidence, (namespace) => {
        const candidates = policies.filter((policy) => policy.metadata.namespace === namespace
          && Object.keys(policy.spec.podSelector?.matchLabels ?? {}).length === 0
          && (policy.spec.podSelector?.matchExpressions ?? []).length === 0);
        return ['Ingress', 'Egress'].every((direction) => candidates.some((policy) => {
          const types = policy.spec.policyTypes ?? ['Ingress', ...(policy.spec.egress ? ['Egress'] : [])];
          return types.includes(direction) && (policy.spec[direction.toLowerCase()] ?? []).length === 0;
        }));
      }, 'Declared all-pod default-deny ingress and egress baselines (not effective policy unions).');
    }
    case 'NET-004':
      return checkAll(scoped(evidence, 'ingresses'), (ingress) => Array.isArray(ingress.tls) && ingress.tls.length > 0,
        'TLS declarations on Ingress resources. Gateway API and upstream termination are not evaluated.');
    case 'NET-005': {
      const slices = scoped(evidence, 'endpointslices');
      const selected = scoped(evidence, 'services').filter((service) => service.type !== 'ExternalName' && Object.keys(service.selector ?? {}).length);
      return checkAll(selected, (service) => {
        const endpoints = slices.filter((slice) => slice.metadata.namespace === service.metadata.namespace
          && slice.serviceName === service.metadata.name).flatMap((slice) => slice.endpoints ?? [])
          .filter((endpoint) => endpoint.addresses?.length > 0);
        return endpoints.some((endpoint) => endpoint.ready === true) ? true
          : endpoints.some((endpoint) => endpoint.ready === undefined || endpoint.ready === null) ? null : false;
      }, 'Service EndpointSlice readiness.');
    }
    case 'NET-006': {
      const profile = cluster.networkProfile;
      if (!profile) return outcome('unknown', 'Network profile is absent.');
      const serviceCidrs = profile.serviceCidrs ?? (profile.serviceCidr ? [profile.serviceCidr] : []);
      const podCidrs = profile.podCidrs ?? (profile.podCidr ? [profile.podCidr] : []);
      if (!serviceCidrs.length || !profile.dnsServiceIP) return outcome('unknown', 'Service CIDRs and DNS IP are required for the comparison.');
      const conflicts = podCidrs.flatMap((pod) => serviceCidrs.filter((service) => overlaps(pod, service)).map((service) => ({ pod, service })));
      const dnsInside = serviceCidrs.some((network) => contains(network, profile.dnsServiceIP));
      return outcome(conflicts.length || !dnsInside ? 'fail' : podCidrs.length ? 'pass' : 'review',
        podCidrs.length ? 'Compared only reported pod/service CIDRs and DNS IP; external address plans were not checked.'
          : 'DNS/service range checked; no pod CIDR was reported for overlap comparison. Review the network model and full address plan.',
        { serviceCidrs, podCidrs, dnsServiceIP: profile.dnsServiceIP, dnsInside, conflicts });
    }
    case 'SEC-001':
      return checkAll(containerEntries(evidence), ({ container, spec }) => container.securityContext?.privileged !== true
        && container.securityContext?.windowsOptions?.hostProcess !== true && spec.securityContext?.windowsOptions?.hostProcess !== true,
      'Privileged and HostProcess settings.');
    case 'SEC-002':
      return linuxCheck(evidence, ({ container }) => container.securityContext?.allowPrivilegeEscalation === false,
        'Linux privilege-escalation declarations; ambiguous OS applicability remains unknown.');
    case 'SEC-003':
      return linuxCheck(evidence, ({ container, spec }) => {
        const nonRoot = container.securityContext?.runAsNonRoot ?? spec.securityContext?.runAsNonRoot;
        const uid = container.securityContext?.runAsUser ?? spec.securityContext?.runAsUser;
        return nonRoot !== false && uid !== 0 && (nonRoot === true || typeof uid === 'number' && uid > 0);
      }, 'Effective Linux non-root declarations.');
    case 'SEC-004':
      return linuxCheck(evidence, ({ container }) => container.securityContext?.capabilities?.drop?.includes('ALL') === true
        && (container.securityContext?.capabilities?.add ?? []).length === 0, 'Linux capability declarations.');
    case 'SEC-005':
      return checkAll(workloads(evidence), ({ pod }) => ![pod.spec.hostNetwork, pod.spec.hostPID, pod.spec.hostIPC].includes(true),
        'Host namespace-sharing declarations.');
    case 'SEC-006':
      return checkAll(workloads(evidence), ({ pod }) => !(pod.spec.volumes ?? []).some((volume) => volume.type === 'hostPath'),
        'HostPath mount declarations.');
    case 'SEC-007':
      return linuxCheck(evidence, ({ container, spec }) => ['RuntimeDefault', 'Localhost'].includes(
        container.securityContext?.seccompProfile?.type ?? spec.securityContext?.seccompProfile?.type), 'Linux seccomp declarations.');
    case 'SEC-008':
      return checkAll(containerEntries(evidence), ({ container }) => {
        if (typeof container.image !== 'string') return null;
        if (/@sha256:[0-9a-f]{64}$/i.test(container.image)) return true;
        const name = container.image.split('/').at(-1);
        return name.includes(':') && name.split(':').at(-1).toLowerCase() !== 'latest' && !name.includes('@');
      }, 'Explicit image-version references; signatures and vulnerabilities are not evaluated.');
    case 'SEC-009': return flag(cluster.securityProfile?.defender?.securityMonitoring?.enabled, 'Defender security-monitoring enablement.');
    case 'WK-001': return resourceCheck(evidence, 'requests');
    case 'WK-002': return resourceCheck(evidence, 'limits');
    case 'WK-003':
      return checkAll(containerEntries(evidence, { longRunning: true, init: false, ephemeral: false }),
        ({ container }) => container.probes?.readiness === true && container.probes?.liveness === true,
        'Readiness/liveness probe declarations for long-running containers.');
    case 'WK-004':
      return checkAll(containerEntries(evidence, { ephemeral: false }), ({ container }) => {
        const comparisons = ['cpu', 'memory'].map((resource) =>
          compareQuantities(container.resources?.requests?.[resource], container.resources?.limits?.[resource]));
        if (comparisons.includes(1)) return false;
        return comparisons.includes(null) ? null : true;
      }, 'CPU/memory request <= limit comparisons.');
    case 'WK-005':
      return checkAll(scoped(evidence, 'deployments').filter((w) => w.replicas > 0), (workload) => {
        if (typeof workload.availableReplicas !== 'number' || typeof workload.observedGeneration !== 'number'
          || typeof workload.metadata.generation !== 'number') return null;
        return workload.availableReplicas >= workload.replicas && workload.observedGeneration >= workload.metadata.generation;
      }, 'Point-in-time Deployment generation and availability.');
    case 'WK-006':
      return checkAll(scoped(evidence, 'hpas'), (hpa) => Number.isInteger(hpa.minReplicas) && Number.isInteger(hpa.maxReplicas)
        ? hpa.minReplicas >= 0 && hpa.maxReplicas >= 1 && hpa.minReplicas <= hpa.maxReplicas : null, 'HPA replica bounds.');
    case 'WK-007': {
      const pods = scoped(evidence, 'pods');
      const result = checkAll(pods, (pod) => {
        if (!pod.phase) return null;
        return !['Failed', 'Unknown'].includes(pod.phase) && !(pod.containerStatuses ?? []).some(
          (status) => ['CrashLoopBackOff', 'ImagePullBackOff', 'ErrImagePull', 'CreateContainerConfigError', 'CreateContainerError'].includes(status.waitingReason));
      }, 'Application pod failure-state snapshot.');
      if (result.status === 'pass' && pods.some((pod) => pod.phase === 'Pending')) {
        return outcome('review', 'No explicit failure reason was found, but Pending pods require scheduling and age review.',
          observedList(pods.filter((pod) => pod.phase === 'Pending').map(ref)));
      }
      return result;
    }
    case 'REL-001':
      return checkAll(services(evidence), (workload) => workload.replicas >= 2, 'Production service replica counts.');
    case 'REL-002':
      return checkAll(services(evidence).filter((workload) => workload.replicas >= 2), (workload) => scoped(evidence, 'pdbs')
        .some((pdb) => pdb.metadata.namespace === workload.metadata.namespace && matchesSelector(workload.pod.labels, pdb.spec.selector)),
      'Namespace-local PDB selector coverage.');
    case 'REL-003':
      return checkAll(services(evidence).filter((workload) => workload.replicas >= 2), ({ pod }) =>
        (pod.spec.topologySpreadConstraints ?? []).some((constraint) => Boolean(constraint.topologyKey))
        || (pod.spec.podAntiAffinity?.requiredDuringSchedulingIgnoredDuringExecution ?? []).length > 0
        || (pod.spec.podAntiAffinity?.preferredDuringSchedulingIgnoredDuringExecution ?? []).length > 0,
      'Topology-aware placement declarations, not effective physical spreading.');
    case 'REL-004':
      if (automatic(evidence)) return outcome('review', 'Review service-managed AKS Automatic zone placement with current platform evidence.');
      return checkAll(items(evidence, 'nodepools'), (pool) => Array.isArray(pool.availabilityZones) ? new Set(pool.availabilityZones).size >= 2 : null,
        'Declared cloud pool zone diversity.');
    case 'REL-005': {
      const allServices = services(evidence);
      return checkAll(scoped(evidence, 'pdbs'), (pdb) => {
        const selected = allServices.filter((workload) => workload.metadata.namespace === pdb.metadata.namespace
          && matchesSelector(workload.pod.labels, pdb.spec.selector));
        const total = selected.reduce((sum, workload) => sum + workload.replicas, 0);
        if (!total || pdb.status?.expectedPods !== total) return null;
        if (pdb.spec.minAvailable !== undefined) return pbdCount(pdb.spec.minAvailable, total) < total;
        if (pdb.spec.maxUnavailable !== undefined) return pbdCount(pdb.spec.maxUnavailable, total) > 0;
        return null;
      }, 'PDB zero-voluntary-disruption configuration; unknown target sets require manual review.');
    }
    case 'ST-001':
      return checkAll(scoped(evidence, 'pvcs'), (pvc) => typeof pvc.phase === 'string' ? pvc.phase === 'Bound' : null, 'PVC binding state.');
    case 'ST-002':
      return checkAll(items(evidence, 'storageclasses').filter((sc) => sc.provisioner === 'disk.csi.azure.com'),
        (sc) => typeof sc.volumeBindingMode === 'string' ? sc.volumeBindingMode === 'WaitForFirstConsumer' : null,
        'Azure Disk CSI volume binding mode.');
    case 'OBS-001': {
      const settings = items(evidence, 'diagnostics');
      const routed = settings.filter((setting) => [setting.workspaceId, setting.storageAccountId, setting.eventHubAuthorizationRuleId,
        setting.marketplacePartnerId].some(Boolean) && (setting.logs ?? []).some((log) => log.enabled === true
          && (['kube-audit', 'kube-audit-admin'].includes(log.category) || ['audit', 'allLogs'].includes(log.categoryGroup))));
      return outcome(routed.length ? 'pass' : 'fail', 'Audit diagnostic routing configuration, not observed ingestion or full audit coverage.',
        { settings: settings.length, routedSettings: routed.map((setting) => setting.name) });
    }
    case 'OBS-002': return flag(cluster.azureMonitorProfile?.metrics?.enabled, 'Managed Prometheus collection enablement.');
    case 'OBS-003': return flag(cluster.addonProfiles?.omsagent?.enabled, 'Container insights add-on enablement.');
    case 'GOV-001': return flag(cluster.addonProfiles?.azurepolicy?.enabled, 'Azure Policy add-on enablement.');
    case 'GOV-002':
      return namespaceCheck(evidence, (namespace) => scoped(evidence, 'resourcequotas').some((quota) => quota.metadata.namespace === namespace
        && Object.keys(quota.hard ?? {}).length > 0), 'ResourceQuota declarations on workload namespaces.');
    case 'CST-001': {
      if (cluster.nodeProvisioningProfile?.mode === 'Auto') return outcome('pass', 'Node auto-provisioning mode Auto is explicitly configured.');
      return checkAll(items(evidence, 'nodepools').filter((pool) => pool.mode === 'User'),
        (pool) => typeof pool.enableAutoScaling === 'boolean' ? pool.enableAutoScaling : null, 'User-pool autoscaling enablement.');
    }
    case 'CST-002':
      return checkAll(items(evidence, 'nodepools').filter((pool) => pool.enableAutoScaling === true), (pool) => {
        if (!Number.isInteger(pool.minCount) || !Number.isInteger(pool.maxCount)) return null;
        return pool.minCount >= 0 && pool.maxCount > 0 && pool.minCount <= pool.maxCount;
      }, 'Autoscaler bounds, excluding temporary observed surge counts.');
    case 'LC-001': {
      const channel = cluster.autoUpgradeProfile?.upgradeChannel;
      if (typeof channel !== 'string') return outcome('unknown', 'Kubernetes upgrade channel was not observed.');
      return outcome(channel && channel !== 'none' ? 'pass' : 'fail', 'Kubernetes auto-upgrade channel configuration.', { channel });
    }
    case 'LC-002': {
      const channel = cluster.autoUpgradeProfile?.nodeOsUpgradeChannel ?? cluster.autoUpgradeProfile?.nodeOSUpgradeChannel;
      if (typeof channel !== 'string') return outcome('unknown', 'Node OS update channel was not observed.');
      return outcome(['SecurityPatch', 'NodeImage'].includes(channel) ? 'pass' : 'fail', 'Node OS update channel configuration.', { channel });
    }
    case 'LC-003': {
      const windows = items(evidence, 'maintenance');
      return checkAll(['aksManagedAutoUpgradeSchedule', 'aksManagedNodeOSUpgradeSchedule'],
        (name) => windows.some((window) => window.name === name && Object.keys(window.maintenanceWindow ?? {}).length > 0),
        'Separate Kubernetes and node OS managed-upgrade maintenance definitions.');
    }
    case 'LOC-001':
      if (typeof cluster.provisioningState !== 'string') return outcome('unknown', 'Local provisioning state was not observed.');
      return outcome(cluster.provisioningState === 'Succeeded' ? 'pass' : 'fail', 'Local ARM provisioning state.', { provisioningState: cluster.provisioningState });
    case 'LOC-002':
      if (!Number.isInteger(cluster.controlPlane?.count)) return outcome('unknown', 'Local controlPlane.count was not observed.');
      return outcome([3, 5].includes(cluster.controlPlane.count) ? 'pass' : 'fail', 'Local production control-plane redundancy.', { count: cluster.controlPlane.count });
    case 'ACT-001': {
      const data = evidence.sources.activeConnectivity.data;
      if (typeof data.resolved !== 'boolean' || typeof data.markerMatched !== 'boolean' || !Number.isInteger(data.httpStatus)) {
        throw new Error('Incomplete connectivity measurements.');
      }
      return outcome(data.resolved && data.httpStatus === 200 && data.markerMatched ? 'pass' : 'fail',
        'Isolated probe-to-service DNS and HTTP path only.', data);
    }
    case 'ACT-002': {
      const data = evidence.sources.activeE2E.data;
      if (!Number.isInteger(data.attempted) || !Number.isInteger(data.successes)) throw new Error('Incomplete end-to-end request counts.');
      return outcome(data.attempted === 3 && data.successes === 3 ? 'pass' : 'fail', 'Three synthetic loopback port-forward requests.', data);
    }
    case 'ACT-003': {
      const statistics = loadStatistics(evidence.sources.activeLoad.data);
      return outcome(statistics.withinBudgets ? 'pass' : 'fail', 'Measured load-smoke budgets; these are operator budgets, not Microsoft SLOs.', statistics);
    }
    case 'ACT-004': {
      const data = evidence.sources.activeSecurity.data;
      if (typeof data.denied !== 'boolean' || data.dryRun !== true || typeof data.reason !== 'string') {
        throw new Error('Incomplete server-side admission-test evidence.');
      }
      return outcome(data.denied && data.reason === 'restricted-pod-security' ? 'pass' : 'fail',
        'Restricted Pod Security Admission in the synthetic namespace only; no exploitation was attempted.', data);
    }
    default: throw new Error(`Missing automated evaluator: ${id}`);
  }
}

export function manualObservation(control, evidence) {
  const observed = {};
  for (const id of control.requires) {
    let values = items(evidence, id);
    if (id === 'cluster') {
      observed.cluster = evidence.sources.cluster.data;
      continue;
    }
    if (id === 'clusterrolebindings') values = values.filter((binding) => binding.roleRef?.name === 'cluster-admin');
    if (id === 'events') values = values.filter((event) => event.type === 'Warning');
    observed[id] = observedList(values);
  }
  return outcome('review', 'Independent owner/operational evidence is required. Static inventory cannot establish this conclusion.', observed);
}
