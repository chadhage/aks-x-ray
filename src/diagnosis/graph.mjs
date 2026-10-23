import { createHash } from 'node:crypto';
import { validateEvidence } from '../evidence.mjs';
import { binding, requiredSources, targetClusterId } from '../collector.mjs';
import { inScope, kubernetesResources, namespacedSources, workloadSources } from '../projection.mjs';
import { approvedResourceSubscription, strategyFor } from '../scope.mjs';

export const canonical = (value) => JSON.stringify(value, (_, item) => item && typeof item === 'object' && !Array.isArray(item)
  ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b, 'en'))) : item);
export const stableId = (kind, value) => `${kind}:${createHash('sha256').update(canonical(value)).digest('hex').slice(0, 24)}`;
export const armId = (id) => `arm:${id.replace(/\/$/, '').toLowerCase()}`;
export const kubeId = (cluster, kind, namespace, name) => `k8s:${cluster.toLowerCase()}:${kind.toLowerCase()}:${namespace ?? ''}/${encodeURIComponent(name)}`;
export const principalId = (tenant, id) => `principal:${tenant.toLowerCase()}:${id.toLowerCase()}`;

export function fact(node, key) {
  const values = node?.facts?.[key] ?? [];
  if (!values.length) return { status: 'unknown', evidenceRefs: [] };
  const unique = new Map(values.map((item) => [canonical(item.value), item.value]));
  return { status: unique.size === 1 ? 'known' : 'conflicting',
    ...(unique.size === 1 ? { value: [...unique.values()][0] } : {}),
    evidenceRefs: [...new Set(values.map((item) => item.evidenceRef))].sort() };
}

export function wildcardMatch(pattern, value) {
  if (typeof pattern !== 'string' || typeof value !== 'string') return false;
  const parts = pattern.toLowerCase().split('*');
  const text = value.toLowerCase();
  let offset = 0;
  if (!text.startsWith(parts[0])) return false;
  offset = parts[0].length;
  for (const part of parts.slice(1, -1)) {
    const found = text.indexOf(part, offset);
    if (found < 0) return false;
    offset = found + part.length;
  }
  return parts.length === 1 ? text === parts[0] : text.slice(offset).endsWith(parts.at(-1));
}

export function permissionAllows(permissions, action, data = false) {
  if (!Array.isArray(permissions)) return null;
  let unknown = false;
  for (const permission of permissions) {
    const actions = permission[data ? 'dataActions' : 'actions'];
    const excluded = permission[data ? 'notDataActions' : 'notActions'] ?? [];
    if (!Array.isArray(actions) || !Array.isArray(excluded)) { unknown = true; continue; }
    if (actions.some((pattern) => wildcardMatch(pattern, action)) && !excluded.some((pattern) => wildcardMatch(pattern, action))) return true;
  }
  return unknown ? null : false;
}

const azureCapabilities = [
  { type: 'microsoft.storage/storageaccounts', name: 'read-blob-data', action: 'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read', data: true },
  { type: 'microsoft.keyvault/vaults', name: 'read-vault-secrets', action: 'Microsoft.KeyVault/vaults/secrets/getSecret/action', data: true },
  { type: 'microsoft.containerservice/managedclusters', name: 'list-cluster-admin-credentials', action: 'Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action' },
  { type: 'microsoft.containerservice/managedclusters', name: 'modify-cluster', action: 'Microsoft.ContainerService/managedClusters/write' }
];
const kubeCapabilities = [
  { name: 'read-secrets', group: '', resources: ['secrets'], verbs: ['get', 'list', 'watch'] },
  { name: 'create-pods', group: '', resources: ['pods'], verbs: ['create'] },
  { name: 'exec-pods', group: '', resources: ['pods/exec', '*/*'], verbs: ['create', 'get'] },
  { name: 'escalate-rbac', group: 'rbac.authorization.k8s.io', resources: ['roles', 'clusterroles'], verbs: ['bind', 'escalate'] }
];

export class GraphLimitError extends Error {
  constructor(graph) {
    super('Resource/identity graph exceeded its configured node or edge limit.');
    this.code = 'GRAPH_LIMIT';
    this.graph = graph;
  }
}

export function buildGraph(inputs, options = {}) {
  if (!Array.isArray(inputs) || !inputs.length || inputs.length > 100) throw new Error('A graph requires 1-100 evidence bundles.');
  const bundles = inputs.map(validateEvidence).sort((a, b) => a.sources.cluster?.data?.id?.localeCompare(b.sources.cluster?.data?.id ?? '', 'en')
    || a.target.cluster.localeCompare(b.target.cluster, 'en'));
  if (new Set(bundles.map((bundle) => bundle.synthetic)).size !== 1) throw new Error('Do not mix synthetic and real graph evidence.');
  const tenants = [...new Set(bundles.map((bundle) => bundle.target.tenant?.toLowerCase()).filter(Boolean))];
  const tenant = options.tenant?.toLowerCase() ?? (tenants.length === 1 ? tenants[0] : null);
  if (tenants.length > 1 || tenant && tenants.some((value) => value !== tenant)) throw new Error('Evidence is outside the approved tenant.');
  const subscriptions = [...new Set(options.subscriptions ?? bundles.flatMap((bundle) =>
    bundle.scope.authorizedSubscriptions ?? [bundle.target.subscription]))].map((value) => value.toLowerCase()).sort();
  for (const bundle of bundles) {
    if ((bundle.scope.authorizedSubscriptions ?? [bundle.target.subscription]).some((id) => !subscriptions.includes(id.toLowerCase()))) {
      throw new Error('Evidence contains an unapproved subscription.');
    }
    for (const id of ['relatedResources', 'resourceGraph']) {
      for (const item of bundle.sources[id]?.data?.items ?? []) approvedResourceSubscription(item.id, subscriptions);
    }
  }
  const nodes = new Map();
  const edges = new Map();
  const sources = new Map();
  const gaps = new Map();
  const clusters = [];
  const targets = [];
  const maximumNodes = options.maxNodes ?? 20_000;
  const maximumEdges = options.maxEdges ?? 50_000;
  const gap = (code, details) => {
    const item = { code, ...details };
    gaps.set(stableId('gap', item), item);
  };
  const finish = () => ({
    schemaVersion: '1.0', scope: { tenant, subscriptions, clusters: [...new Set(clusters)].sort(),
      targets: [...targets].sort((a, b) => canonical(a).localeCompare(canonical(b), 'en')) },
    synthetic: bundles[0].synthetic, incomplete: gaps.size > 0,
    nodes: [...nodes.values()].map((node) => ({ ...node,
      evidenceRefs: [...node.evidenceRefs].sort(),
      facts: Object.fromEntries(Object.entries(node.facts).sort(([a], [b]) => a.localeCompare(b, 'en'))
        .map(([key, observations]) => [key, [...observations].sort((a, b) => canonical(a).localeCompare(canonical(b), 'en'))])) }))
      .sort((a, b) => a.id.localeCompare(b.id, 'en')),
    edges: [...edges.values()].map((edge) => ({ ...edge, evidenceRefs: [...edge.evidenceRefs].sort() })).sort((a, b) => a.id.localeCompare(b.id, 'en')),
    sources: [...sources.values()].sort((a, b) => a.id.localeCompare(b.id, 'en')),
    gaps: [...gaps.values()].sort((a, b) => canonical(a).localeCompare(canonical(b), 'en'))
  });
  const limit = () => {
    gap('GRAPH_LIMIT', { reason: 'Configured graph size limit reached; this is partial evidence, not a completed inventory.' });
    throw new GraphLimitError(finish());
  };
  const addNode = (id, kind, name, attributes = {}, values = {}, ref) => {
    let node = nodes.get(id);
    if (!node) {
      if (nodes.size >= maximumNodes) limit();
      node = { id, kind, name, ...attributes, facts: {}, evidenceRefs: new Set() };
      nodes.set(id, node);
    }
    if (ref) node.evidenceRefs.add(ref.id);
    for (const [key, value] of Object.entries(values)) {
      if (value === undefined || !ref) continue;
      const observations = node.facts[key] ??= [];
      const observation = { value: structuredClone(value), evidenceRef: ref.id };
      if (!observations.some((existing) => canonical(existing) === canonical(observation))) observations.push(observation);
    }
    return node;
  };
  const addEdge = (from, to, relationship, refs, attributes = {}, state = 'observed') => {
    if (!nodes.has(from) || !nodes.has(to)) throw new Error('A graph edge requires both endpoint nodes.');
    const id = stableId('edge', [from, to, relationship, state, attributes]);
    let edge = edges.get(id);
    if (!edge) {
      if (edges.size >= maximumEdges) limit();
      edge = { id, from, to, relationship, state, ...attributes, evidenceRefs: new Set() };
      edges.set(id, edge);
    }
    for (const ref of refs) if (ref) edge.evidenceRefs.add(typeof ref === 'string' ? ref : ref.id);
    return edge;
  };
  const addAzureIdentity = (owner, identity, ref, cluster, defaultTenant) => {
    if (!identity) return;
    const identityTenant = identity.tenantId ?? defaultTenant;
    const principals = [
      identity.principalId,
      ...Object.values(identity.userAssignedIdentities ?? {}).map((item) => item.principalId)
    ].filter(Boolean);
    for (const principal of new Set(principals)) {
      const id = principalId(identityTenant ?? `unknown-${cluster}`, principal);
      addNode(id, 'azure-principal', principal, { tenant: identityTenant ?? null, principalObjectId: principal },
        { identityType: identity.type }, ref);
      addEdge(owner, id, 'uses-identity', [ref], {}, 'observed');
    }
  };
  const addAsset = (resource, ref, cluster) => {
    const subscription = approvedResourceSubscription(resource.id, subscriptions);
    const id = armId(resource.id);
    const node = addNode(id, 'azure-resource', resource.name, { resourceId: resource.id.toLowerCase(), subscription,
      resourceType: resource.type.toLowerCase() }, { configuration: resource.configuration, supported: resource.supported }, ref);
    addAzureIdentity(id, resource.identity, ref, cluster, tenant);
    if (resource.type.toLowerCase() === 'microsoft.managedidentity/userassignedidentities') {
      const configuration = resource.configuration ?? {};
      addAzureIdentity(id, { ...configuration, type: 'UserAssigned' }, ref, cluster, configuration.tenantId ?? tenant);
    }
    return node;
  };
  const contexts = [];
  for (const evidence of bundles) {
    const clusterData = evidence.sources.cluster?.data;
    const cluster = clusterData?.id ?? targetClusterId(evidence.target);
    approvedResourceSubscription(cluster, subscriptions);
    clusters.push(cluster.toLowerCase());
    const targetBinding = binding(evidence);
    targets.push({ clusterId: cluster.toLowerCase(), context: evidence.target.context, bindingStatus: targetBinding.status,
      bindingMode: targetBinding.mode ?? 'cross-plane', namespaces: evidence.scope.namespaces === null ? null : [...evidence.scope.namespaces].sort(),
      excludedNamespaces: [...evidence.scope.excludedNamespaces].sort() });
    const refs = new Map();
    const expected = new Set(requiredSources({ ...evidence.scope, assessmentStrategies: options.strategies ?? ['graph'] }, evidence.target.platform)
      .filter((id) => !id.startsWith('active')));
    for (const sourceId of new Set([...expected, ...Object.keys(evidence.sources)])) {
      const record = evidence.sources[sourceId];
      const authorized = !evidence.scope.strategies || evidence.scope.strategies.includes(strategyFor(sourceId, evidence.scope));
      const status = authorized ? record?.status ?? 'missing' : 'notCollected';
      const data = record?.data;
      const ordered = data?.items ? { ...data, items: [...data.items].sort((a, b) => canonical(a).localeCompare(canonical(b), 'en')) } : data;
      const digest = createHash('sha256').update(canonical(ordered ?? null)).digest('hex');
      const ref = {
        id: stableId('evidence', [cluster.toLowerCase(), sourceId, record?.collectedAt ?? evidence.collectedAt, status, digest]),
        clusterId: cluster.toLowerCase(), sourceId, status, collectedAt: record?.collectedAt ?? evidence.collectedAt,
        pointer: `/sources/${sourceId}/data`, bindingStatus: targetBinding.status, digest, required: expected.has(sourceId),
        commands: record?.commands ?? []
      };
      refs.set(sourceId, ref);
      sources.set(ref.id, ref);
      if (expected.has(sourceId) && status !== 'ok') gap('SOURCE_UNAVAILABLE', { clusterId: cluster.toLowerCase(), sourceId, status,
        reason: !authorized ? 'Collection strategy was not authorized.' : record?.error?.message ?? record?.reason ?? 'Evidence was not collected.' });
    }
    const available = (id) => refs.get(id)?.status === 'ok' || refs.get(id)?.status === 'error' && Array.isArray(evidence.sources[id]?.data?.items);
    const items = (id) => available(id) ? evidence.sources[id]?.data?.items ?? [] : [];
    const clusterNode = addNode(armId(cluster), 'cluster', evidence.target.cluster, {
      resourceId: cluster.toLowerCase(), resourceType: clusterData?.type?.toLowerCase() ?? 'unverified',
      clusterId: cluster.toLowerCase(), subscription: evidence.target.subscription.toLowerCase(),
      ...(evidence.sources.cluster?.status !== 'ok' ? { unresolved: true } : {})
    }, clusterData ? { apiServerAccessProfile: clusterData.apiServerAccessProfile, disableLocalAccounts: clusterData.disableLocalAccounts,
      oidcIssuerProfile: clusterData.oidcIssuerProfile, securityProfile: clusterData.securityProfile } : {}, refs.get('cluster'));
    addAzureIdentity(clusterNode.id, clusterData?.identity, refs.get('cluster'), cluster, evidence.target.tenant);
    const kubelet = clusterData?.identityProfile?.kubeletidentity;
    if (kubelet?.objectId) addAzureIdentity(clusterNode.id, { principalId: kubelet.objectId, type: 'Kubelet' }, refs.get('cluster'), cluster, evidence.target.tenant);
    for (const id of ['relatedResources', 'resourceGraph']) {
      for (const resource of items(id)) addAsset(resource, refs.get(id), cluster);
    }
    for (const linked of clusterData?.linkedResourceIds ?? []) {
      try { approvedResourceSubscription(linked, subscriptions); }
      catch (error) { gap('REFERENCE_OUT_OF_SCOPE', { clusterId: cluster.toLowerCase(), reason: error.message }); continue; }
      if (!nodes.has(armId(linked))) addNode(armId(linked), 'azure-reference', linked, { resourceId: linked.toLowerCase(), unresolved: true }, {}, refs.get('cluster'));
      addEdge(clusterNode.id, armId(linked), 'references', [refs.get('cluster')]);
    }
    if (targetBinding.status !== 'verified' || targetBinding.mode === 'arm-only') {
      gap(targetBinding.mode === 'arm-only' && targetBinding.status === 'verified' ? 'KUBERNETES_NOT_COLLECTED' : 'TARGET_BINDING',
        { clusterId: cluster.toLowerCase(), status: targetBinding.mode === 'arm-only' ? 'notCollected' : targetBinding.status, reason: targetBinding.message });
    } else {
      const kubeNodes = new Map();
      for (const sourceId of Object.keys(kubernetesResources)) {
        for (const item of items(sourceId)) {
          const namespace = sourceId === 'namespaces' ? item.metadata.name : item.metadata.namespace;
          if ((namespacedSources.has(sourceId) || sourceId === 'namespaces') && !inScope(namespace, evidence.scope)) continue;
          const kind = item.kind ?? sourceId;
          const id = kubeId(cluster, kind, item.metadata.namespace, item.metadata.name);
          const type = workloadSources.includes(sourceId) ? 'workload' : sourceId === 'serviceaccounts' ? 'service-account'
            : ['roles', 'clusterroles'].includes(sourceId) ? 'kubernetes-role'
              : ['rolebindings', 'clusterrolebindings'].includes(sourceId) ? 'role-binding'
                : sourceId === 'services' ? 'service' : sourceId === 'namespaces' ? 'namespace' : sourceId;
          const values = sourceId === 'serviceaccounts' ? { automountServiceAccountToken: item.automountServiceAccountToken, workloadIdentity: item.workloadIdentity }
            : workloadSources.includes(sourceId) ? { pod: item.pod, phase: item.phase }
              : sourceId === 'services' ? { selector: item.selector, type: item.type, internal: item.internal, externalIPs: item.externalIPs,
                loadBalancerIngress: item.loadBalancerIngress }
                : ['roles', 'clusterroles'].includes(sourceId) ? { rules: item.rules } : { labels: item.metadata.labels };
          addNode(id, type, item.metadata.name, { clusterId: cluster.toLowerCase(), namespace: item.metadata.namespace ?? null, kubernetesKind: kind }, values, refs.get(sourceId));
          kubeNodes.set(id, { item, sourceId });
          addEdge(clusterNode.id, id, 'contains', [refs.get(sourceId)]);
        }
      }
      for (const [id, { item, sourceId }] of kubeNodes) {
        if (workloadSources.includes(sourceId)) {
          const accountName = item.pod.spec.serviceAccountName || 'default';
          const accountId = kubeId(cluster, 'ServiceAccount', item.metadata.namespace, accountName);
          if (!nodes.has(accountId)) {
            addNode(accountId, 'service-account', accountName, { clusterId: cluster.toLowerCase(), namespace: item.metadata.namespace, unresolved: true }, {}, refs.get(sourceId));
            gap('UNRESOLVED_SERVICE_ACCOUNT', { clusterId: cluster.toLowerCase(), subject: id });
          }
          const token = typeof item.pod.spec.automountServiceAccountToken === 'boolean' ? item.pod.spec.automountServiceAccountToken
            : fact(nodes.get(accountId), 'automountServiceAccountToken').status === 'known' ? fact(nodes.get(accountId), 'automountServiceAccountToken').value
              : nodes.get(accountId).unresolved ? null : true;
          addEdge(id, accountId, 'uses-service-account', [refs.get(sourceId), refs.get('serviceaccounts')], {
            tokenAutomountConfigured: token
          }, sourceId === 'pods' ? 'observed' : 'configured');
        }
        if (sourceId === 'services') {
          if (item.type === 'LoadBalancer' && item.internal !== 'true'
            && (item.loadBalancerIngress ?? []).some((entry) => entry.hostname || entry.ip && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fd|fc|fe80:)/i.test(entry.ip))) {
            addNode('external:internet', 'external', 'Internet');
            addEdge('external:internet', id, 'configured-public-entry', [refs.get(sourceId)],
              { reachabilityValidated: false, constraints: ['Firewall, routing, policy unions and initial access are not established.'] }, 'configured');
          }
          for (const [podId, pod] of kubeNodes) {
            if (pod.sourceId !== 'pods' || pod.item.metadata.namespace !== item.metadata.namespace || !Object.keys(item.selector ?? {}).length) continue;
            if (Object.entries(item.selector).every(([key, value]) => pod.item.pod.labels[key] === value)) addEdge(id, podId, 'selects', [refs.get(sourceId), refs.get('pods')]);
          }
        }
      }
      for (const [accountId, { item, sourceId }] of kubeNodes) {
        if (sourceId !== 'serviceaccounts') continue;
        for (const group of ['system:authenticated', 'system:serviceaccounts', `system:serviceaccounts:${item.metadata.namespace}`]) {
          const groupId = kubeId(cluster, 'Identity-Group', undefined, group);
          addNode(groupId, 'kubernetes-identity', group, { clusterId: cluster.toLowerCase(), identityKind: 'Group', namespace: null }, {}, refs.get(sourceId));
          addEdge(accountId, groupId, 'member-of', [refs.get(sourceId)],
            { basis: 'Kubernetes service-account authentication contract; not external Entra group inference.' }, 'configured');
        }
      }
      for (const sourceId of ['rolebindings', 'clusterrolebindings']) {
        for (const item of items(sourceId)) {
          if (sourceId === 'rolebindings' && !inScope(item.metadata.namespace, evidence.scope)) continue;
          const bindingId = kubeId(cluster, item.kind ?? (sourceId === 'rolebindings' ? 'RoleBinding' : 'ClusterRoleBinding'), item.metadata.namespace, item.metadata.name);
          const roleId = kubeId(cluster, item.roleRef?.kind ?? 'UnknownRole',
            item.roleRef?.kind === 'Role' ? item.metadata.namespace : undefined, item.roleRef?.name ?? 'unresolved');
          const role = nodes.get(roleId);
          if (!role) {
            addNode(roleId, 'kubernetes-role', item.roleRef?.name ?? 'unresolved', { clusterId: cluster.toLowerCase(), unresolved: true }, {}, refs.get(sourceId));
            gap('UNRESOLVED_ROLE', { clusterId: cluster.toLowerCase(), subject: bindingId });
          }
          if (!nodes.has(bindingId)) continue;
          addEdge(bindingId, roleId, 'references-role', [refs.get(sourceId)], {}, role ? 'observed' : 'conditional');
          for (const subject of item.subjects ?? []) {
            const subjectId = subject.kind === 'ServiceAccount' ? kubeId(cluster, 'ServiceAccount', subject.namespace ?? item.metadata.namespace, subject.name)
              : kubeId(cluster, `Identity-${subject.kind}`, undefined, subject.name);
            addNode(subjectId, subject.kind === 'ServiceAccount' ? 'service-account' : 'kubernetes-identity', subject.name,
              { clusterId: cluster.toLowerCase(), namespace: subject.namespace ?? null, identityKind: subject.kind,
                ...(subject.kind === 'ServiceAccount' && !nodes.has(subjectId) ? { unresolved: true } : {}) }, {}, refs.get(sourceId));
            addEdge(subjectId, bindingId, 'bound-via', [refs.get(sourceId)]);
            const rules = fact(role, 'rules');
            if (rules.status !== 'known' || !Array.isArray(rules.value)) continue;
            for (const capability of kubeCapabilities) {
              const matched = rules.value.filter((rule) => Array.isArray(rule.apiGroups) && (rule.apiGroups.includes('*') || rule.apiGroups.includes(capability.group))
                && Array.isArray(rule.resources) && (rule.resources.includes('*') || capability.resources.some((resource) => rule.resources.includes(resource)))
                && Array.isArray(rule.verbs) && (rule.verbs.includes('*') || capability.verbs.some((verb) => rule.verbs.includes(verb))));
              if (!matched.length) continue;
              const validRules = matched.filter((rule) => rule.resourceNames === undefined
                || Array.isArray(rule.resourceNames) && rule.resourceNames.every((name) => typeof name === 'string'));
              if (validRules.length !== matched.length) gap('UNRESOLVED_RESOURCE_NAMES', { subject: roleId });
              if (!validRules.length) continue;
              const resourceNames = validRules.some((rule) => !rule.resourceNames?.length) ? [] : [...new Set(validRules.flatMap((rule) => rule.resourceNames))].sort();
              const namespace = sourceId === 'clusterrolebindings' ? '*' : item.metadata.namespace;
              const capId = stableId('capability', [cluster.toLowerCase(), capability.name, namespace, roleId]);
              addNode(capId, 'capability', capability.name, { capability: capability.name, clusterId: cluster.toLowerCase(), namespace, resourceNames }, {}, refs.get(sourceId));
              addEdge(subjectId, capId, 'grants-capability', [refs.get(sourceId), ...rules.evidenceRefs],
                { via: [bindingId, roleId], effectivePermissionValidated: false }, 'configured');
            }
          }
        }
      }
      for (const [id, { item, sourceId }] of kubeNodes) {
        if (sourceId !== 'serviceaccounts' || !item.workloadIdentity?.clientId) continue;
        const identities = [...nodes.values()].filter((node) => node.resourceType === 'microsoft.managedidentity/userassignedidentities'
          && fact(node, 'configuration').value?.clientId === item.workloadIdentity.clientId);
        let matched = false;
        for (const identity of identities) {
          const identityData = fact(identity, 'configuration').value;
          if (!identityData?.principalId || clusterData.oidcIssuerProfile?.enabled !== true || clusterData.securityProfile?.workloadIdentity?.enabled !== true) continue;
          const credential = items('federatedCredentials').find((value) => value.identityResourceId?.toLowerCase() === identity.resourceId
            && value.issuer === clusterData.oidcIssuerProfile?.issuerUrl && value.subject === `system:serviceaccount:${item.metadata.namespace}:${item.metadata.name}`
            && value.audiences?.includes('api://AzureADTokenExchange'));
          if (!credential) continue;
          const principal = principalId(identityData.tenantId ?? tenant ?? `unknown-${cluster}`, identityData.principalId);
          if (!nodes.has(principal)) continue;
          addEdge(id, principal, 'federates-as', [refs.get(sourceId), refs.get('federatedCredentials'), refs.get('cluster')],
            { tokenExchangeValidated: false }, 'configured');
          matched = true;
        }
        if (!matched) gap('UNVERIFIED_FEDERATION', { clusterId: cluster.toLowerCase(), subject: id, reason: 'Issuer, subject, audience or managed-identity evidence is unresolved.' });
      }
    }
    contexts.push({ evidence, cluster, refs, items });
  }
  const definitions = new Map();
  for (const context of contexts) for (const definition of context.items('roleDefinitions')) {
    const key = (definition.name ?? definition.id?.split('/').at(-1))?.toLowerCase();
    if (key) definitions.set(key, [...(definitions.get(key) ?? []), { definition, ref: context.refs.get('roleDefinitions') }]);
  }
  for (const { evidence, cluster, refs, items } of contexts) {
    for (const assignment of items('roleAssignments')) {
      if (!assignment.principalId || !assignment.scope || !assignment.roleDefinitionId) {
        gap('UNRESOLVED_ASSIGNMENT', { clusterId: cluster.toLowerCase(), sourceId: 'roleAssignments' }); continue;
      }
      const principal = principalId(evidence.target.tenant ?? `unknown-${cluster}`, assignment.principalId);
      addNode(principal, 'azure-principal', assignment.principalId, { tenant: evidence.target.tenant ?? null, principalObjectId: assignment.principalId },
        { principalType: assignment.principalType }, refs.get('roleAssignments'));
      const assignmentId = stableId('assignment', [assignment.id ?? assignment.scope, assignment.principalId, assignment.roleDefinitionId]);
      addNode(assignmentId, 'azure-role-assignment', assignment.id ?? assignmentId, {}, { hasCondition: assignment.hasCondition, grantScope: assignment.scope }, refs.get('roleAssignments'));
      addEdge(principal, assignmentId, 'assigned-role', [refs.get('roleAssignments')], {}, 'configured');
      const scopeId = assignment.scope.toLowerCase().startsWith('/subscriptions/') ? armId(assignment.scope) : `scope:${assignment.scope.toLowerCase()}`;
      if (!nodes.has(scopeId)) addNode(scopeId, 'azure-scope', assignment.scope, { resourceId: assignment.scope.toLowerCase(), unresolved: true }, {}, refs.get('roleAssignments'));
      addEdge(assignmentId, scopeId, 'applies-to', [refs.get('roleAssignments')], {}, 'configured');
      const observed = definitions.get(assignment.roleDefinitionId.split('/').at(-1).toLowerCase()) ?? [];
      if (!observed.length) { gap('UNRESOLVED_AZURE_ROLE', { clusterId: cluster.toLowerCase(), subject: assignmentId }); continue; }
      if (new Set(observed.map((item) => canonical(item.definition.permissions))).size > 1) {
        gap('CONFLICTING_OBSERVATIONS', { subject: assignmentId, reason: 'Role definition snapshots disagree.' }); continue;
      }
      const definition = observed[0].definition;
      const roleId = stableId('azure-role', [tenant, assignment.roleDefinitionId.split('/').at(-1).toLowerCase()]);
      addNode(roleId, 'azure-role', definition.roleName ?? definition.name, {}, { permissions: definition.permissions }, observed[0].ref);
      addEdge(assignmentId, roleId, 'references-role', [refs.get('roleAssignments'), ...observed.map((item) => item.ref)]);
      for (const asset of [...nodes.values()].filter((node) => ['azure-resource', 'cluster'].includes(node.kind))) {
        const scope = assignment.scope.toLowerCase();
        const resource = asset.resourceId;
        const applicable = resource === scope || resource.startsWith(`${scope}/`) || scope.startsWith(`${resource}/`)
          || assignment.queriedResourceId?.toLowerCase() === resource;
        if (!applicable) continue;
        for (const capability of azureCapabilities.filter((item) => item.type === asset.resourceType)) {
          const allowed = permissionAllows(definition.permissions, capability.action, capability.data);
          if (allowed !== true) {
            if (allowed === null) gap('UNRESOLVED_PERMISSION', { subject: assignmentId, capability: capability.name });
            continue;
          }
          const capId = stableId('capability', [principal, resource, scope, capability.name]);
          addNode(capId, 'capability', capability.name, { capability: capability.name, resourceId: resource, grantScope: scope,
            subscription: resource.split('/')[2] }, {}, refs.get('roleAssignments'));
          addEdge(principal, capId, 'grants-capability', [refs.get('roleAssignments'), ...observed.map((item) => item.ref)],
            { via: [assignmentId, roleId, asset.id], effectivePermissionValidated: false,
              constraints: ['Deny assignments, PIM and external authorization controls were not evaluated.'] },
            assignment.hasCondition === false ? 'configured' : 'conditional');
        }
      }
    }
  }
  for (const node of nodes.values()) {
    for (const key of Object.keys(node.facts)) if (fact(node, key).status === 'conflicting') {
      gap('CONFLICTING_OBSERVATIONS', { subject: node.id, property: key, reason: 'Observed values disagree; no last-write-wins value was selected.' });
    }
  }
  return finish();
}

export function validateGraph(graph) {
  if (graph?.schemaVersion !== '1.0' || !graph.scope || !Array.isArray(graph.scope.targets)
    || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges) || !Array.isArray(graph.sources) || !Array.isArray(graph.gaps)) throw new Error('Diagnosis graph shape is invalid.');
  const nodes = new Set(graph.nodes.map((node) => node.id));
  const sources = new Set(graph.sources.map((source) => source.id));
  if (nodes.size !== graph.nodes.length || sources.size !== graph.sources.length
    || new Set(graph.edges.map((edge) => edge.id)).size !== graph.edges.length) throw new Error('Diagnosis graph contains duplicate IDs.');
  for (const source of graph.sources) {
    if (!Number.isFinite(Date.parse(source.collectedAt)) || !['ok', 'error', 'missing', 'notCollected', 'notApplicable'].includes(source.status)) throw new Error('Diagnosis graph evidence provenance is invalid.');
  }
  for (const node of graph.nodes) {
    if (typeof node.id !== 'string' || typeof node.name !== 'string' || typeof node.kind !== 'string' || !node.facts || !Array.isArray(node.evidenceRefs)) throw new Error('Diagnosis graph node is invalid.');
    for (const observations of Object.values(node.facts)) {
      if (!Array.isArray(observations) || observations.some((item) => !sources.has(item.evidenceRef))) throw new Error('Diagnosis graph fact provenance is invalid.');
    }
  }
  for (const edge of graph.edges) {
    if (!nodes.has(edge.from) || !nodes.has(edge.to) || !['observed', 'configured', 'conditional'].includes(edge.state)
      || !Array.isArray(edge.evidenceRefs) || !edge.evidenceRefs.length || edge.evidenceRefs.some((id) => !sources.has(id))) throw new Error('Diagnosis graph edge or provenance is invalid.');
  }
  return graph;
}
