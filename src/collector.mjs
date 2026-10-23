import { createEvidence } from './evidence.mjs';
import { selectControls } from './catalog.mjs';
import { activeSources, kubernetesResources, namespacedSources, projectSource, scopeProjection } from './projection.mjs';
import { runCommand, commandFailure, CommandError } from './process.mjs';
import { accountRecord, approvedResourceSubscription, azureScope, resourceId, strategyFor, validateIdentityScope } from './scope.mjs';
import { isIP } from 'node:net';
import { graphSources } from './diagnosis/strategies.mjs';

export function requiredSources(scope, platform) {
  const configuration = !scope.assessmentStrategies || scope.assessmentStrategies.includes('configuration');
  return [...new Set([
    'context', 'cluster',
    ...(configuration ? selectControls(scope.categories).filter((control) => control.platforms.includes(platform)).flatMap((control) => control.requires) : []),
    ...(scope.assessmentStrategies?.some((id) => id !== 'configuration') ? graphSources : []),
    ...(scope.strategies ? ['accounts',
      ...(scope.strategies.includes('kubernetes') ? ['roles', 'rolebindings', 'clusterroles', 'validatingwebhooks', 'mutatingwebhooks'] : []),
      ...(scope.strategies.includes('iam') ? ['roleAssignments'] : []),
      ...(scope.strategies.includes('iam-inventory') ? ['roleAssignments', 'roleDefinitions', 'federatedCredentials'] : []),
      ...(scope.strategies.includes('policy') ? ['policyStates'] : []),
      ...(scope.strategies.includes('defender') ? ['defenderPricing', 'defenderAssessments'] : []),
      ...(scope.strategies.includes('advisor') ? ['advisorRecommendations'] : []),
      ...(scope.strategies.includes('dependencies') ? ['relatedResources'] : [])] : []),
    ...(scope.strategies?.includes('resource-graph') ? ['resourceGraph'] : [])
  ])];
}

export function targetClusterId(target) {
  const prefix = `/subscriptions/${target.subscription}/resourceGroups/${target.resourceGroup}/providers/`;
  return target.platform === 'cloud' ? `${prefix}Microsoft.ContainerService/managedClusters/${target.cluster}`
    : `${prefix}Microsoft.Kubernetes/connectedClusters/${target.cluster}/providers/Microsoft.HybridContainerService/provisionedClusterInstances/default`;
}

export function commandsFor(id, target, scope, clusterId, resources = []) {
  const azureScope = ['--subscription', target.subscription, '--resource-group', target.resourceGroup];
  const output = ['--output', 'json', '--only-show-errors'];
  if (id === 'accounts') return scope.authorizedSubscriptions.map((subscription) => ({
    file: 'az', args: ['account', 'show', '--subscription', subscription, '--query', '{id:id,tenantId:tenantId,state:state}', ...output]
  }));
  if (['roleAssignments', 'policyStates', 'defenderAssessments', 'advisorRecommendations'].includes(id) && !clusterId) {
    throw new Error(`${id} requires a verified ARM resource ID.`);
  }
  if (id === 'roleAssignments') return [
    ...(scope.strategies?.includes('iam-inventory') ? scope.authorizedSubscriptions.map((subscription) => ({ file: 'az', args: [
      'role', 'assignment', 'list', '--subscription', subscription, '--all', '--fill-principal-name', 'false', '--fill-role-definition-name', 'false', ...output
    ] })) : []),
    { file: 'az', scopeResourceId: clusterId, args: ['role', 'assignment', 'list',
    '--subscription', target.subscription, '--scope', clusterId, '--include-inherited',
    '--fill-principal-name', 'false', '--fill-role-definition-name', 'false', ...output] }];
  if (id === 'roleDefinitions') return scope.authorizedSubscriptions.map((subscription) => ({
    file: 'az', args: ['role', 'definition', 'list', '--subscription', subscription, '--scope', `/subscriptions/${subscription}`, ...output]
  }));
  if (id === 'resourceGraph') return [{ file: 'az', args: ['graph', 'query', '--graph-query', 'Resources',
    '--subscriptions', ...scope.authorizedSubscriptions, '--first', '1000', ...output] }];
  if (id === 'federatedCredentials') {
    const identities = [...new Map(resources.filter((resource) => resource.type?.toLowerCase() === 'microsoft.managedidentity/userassignedidentities')
      .map((resource) => [resource.id.toLowerCase(), resource])).values()];
    if (identities.length > scope.maxRelatedResources) throw new CommandError('RESOURCE_LIMIT', 'Federation metadata exceeds the approved related-resource limit.');
    return identities.map((identity) => {
      const parsed = resourceId(identity.id, scope.authorizedSubscriptions);
      const parts = identity.id.split('/');
      if (!/\/providers\/Microsoft\.ManagedIdentity\/userAssignedIdentities\/[^/]+$/i.test(identity.id)) throw new Error('Managed identity resource ID/type mismatch.');
      return { file: 'az', identityResourceId: identity.id,
        args: ['identity', 'federated-credential', 'list', '--subscription', parsed.subscription,
          '--resource-group', parts[4], '--identity-name', parts.at(-1), ...output] };
    });
  }
  if (id === 'policyStates') return [{ file: 'az', args: ['policy', 'state', 'list',
    '--subscription', target.subscription, '--resource', clusterId, '--all', ...output] }];
  if (id === 'defenderPricing') return [{ file: 'az', args: ['security', 'pricing', 'show',
    '--subscription', target.subscription, '--name', 'Containers', ...output] }];
  if (id === 'defenderAssessments' || id === 'advisorRecommendations') {
    return (scope.authorizedSubscriptions ?? [target.subscription]).map((subscription) => ({
      file: 'az', args: id === 'defenderAssessments'
        ? ['security', 'assessment', 'list', '--subscription', subscription, ...output]
        : ['advisor', 'recommendation', 'list', '--subscription', subscription, ...output]
    }));
  }
  if (id === 'context') return [{
    file: 'kubectl', args: ['config', 'view', '--context', target.context, '--minify', '--output=jsonpath={.clusters[0].cluster.server}'],
    format: 'text'
  }];
  if (id === 'cluster') return [{
    file: 'az', args: [target.platform === 'cloud' ? 'aks' : 'aksarc', 'show', ...azureScope, '--name', target.cluster, '--output', 'json', '--only-show-errors']
  }];
  if (id === 'nodepools') return [{
    file: 'az', args: ['aks', 'nodepool', 'list', ...azureScope, '--cluster-name', target.cluster, '--output', 'json', '--only-show-errors']
  }];
  if (id === 'diagnostics') {
    if (!clusterId) throw new Error('Audit diagnostics collection requires a verified ARM resource ID.');
    return [{ file: 'az', args: ['monitor', 'diagnostic-settings', 'list', '--subscription', target.subscription,
      '--resource', clusterId, '--output', 'json', '--only-show-errors'] }];
  }
  if (id === 'maintenance') return [{
    file: 'az', args: ['aks', 'maintenanceconfiguration', 'list', ...azureScope, '--cluster-name', target.cluster, '--output', 'json', '--only-show-errors']
  }];
  if (id in kubernetesResources) {
    const prefix = ['--context', target.context, '--request-timeout=20s', 'get', kubernetesResources[id]];
    const suffix = ['--output=json', '--chunk-size=200'];
    if (id === 'namespaces' && scope.namespaces !== null) return [{ file: 'kubectl', args: [...prefix, ...scope.namespaces, ...suffix] }];
    if (!namespacedSources.has(id)) return [{ file: 'kubectl', args: [...prefix, ...suffix] }];
    return (scope.namespaces ?? [null]).map((namespace) => ({
      file: 'kubectl', args: [...prefix, ...(namespace ? ['--namespace', namespace] : ['--all-namespaces']), ...suffix]
    }));
  }
  throw new Error(`No read-only command for source ${id}.`);
}

export function binding(evidence) {
  if (evidence.target.tenant) {
    const identity = accountBinding(evidence);
    if (identity.status !== 'verified') return identity;
  }
  const context = evidence.sources.context;
  const cluster = evidence.sources.cluster;
  if (cluster?.status === 'ok') {
    const prefix = `/subscriptions/${evidence.target.subscription}/resourceGroups/${evidence.target.resourceGroup}/providers/`;
    const expectedIds = evidence.target.platform === 'cloud'
      ? [`${prefix}Microsoft.ContainerService/managedClusters/${evidence.target.cluster}`]
      : [`${prefix}Microsoft.HybridContainerService/provisionedClusterInstances/${evidence.target.cluster}`,
        `${prefix}Microsoft.Kubernetes/connectedClusters/${evidence.target.cluster}/providers/Microsoft.HybridContainerService/provisionedClusterInstances/default`];
    if (!expectedIds.some((id) => id.toLowerCase() === cluster.data.id?.toLowerCase())) {
      return { status: 'mismatch', message: 'ARM resource ID differs from the explicitly named subscription, resource group and cluster.' };
    }
    if (evidence.scope.strategies && !evidence.scope.strategies.includes('kubernetes')) {
      return { status: 'verified', mode: 'arm-only', message: 'Tenant, enabled subscription and exact ARM resource ID verified. Kubernetes collection was not authorized.' };
    }
  }
  if (context?.status !== 'ok' || cluster?.status !== 'ok') {
    return { status: 'unverified', message: 'Context or ARM metadata is unavailable; cross-plane target binding is unverified.' };
  }
  const server = new URL(context.data.server);
  if (server.pathname !== '/') return { status: 'unverified', message: 'A path-based proxy endpoint cannot be correlated by hostname alone.' };
  const host = (value) => {
    const name = value.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    return isIP(name) === 6 ? new URL(`https://[${name}]`).hostname.replace(/^\[|\]$/g, '') : name;
  };
  const actual = host(server.hostname);
  const endpoints = evidence.target.platform === 'cloud'
    ? [cluster.data.fqdn, cluster.data.privateFqdn]
    : [cluster.data.controlPlane?.controlPlaneEndpoint?.hostIP];
  const expected = endpoints.filter((value) => typeof value === 'string' && value.length).map(host);
  if (!expected.length) return { status: 'unverified', message: 'ARM metadata contains no supported endpoint for identity correlation.' };
  return expected.includes(actual)
    ? { status: 'verified', message: 'Explicit context endpoint matches the explicit ARM cluster endpoint.', actual, expected }
    : { status: 'mismatch', message: 'Context and ARM cluster endpoints differ. Evidence must not be combined as one cluster.', actual, expected };
}

function accountBinding(evidence) {
  const record = evidence.sources.accounts;
  if (record?.status !== 'ok') return { status: 'unverified', message: 'Tenant/subscription account metadata is unavailable; further collection is blocked.' };
  const { tenant, subscriptions } = azureScope(evidence.target.tenant, evidence.scope.authorizedSubscriptions);
  try {
    if (record.data.items.length !== subscriptions.length) throw new Error('Account inventory does not match the authorized subscriptions.');
    for (let index = 0; index < subscriptions.length; index++) accountRecord(record.data.items[index], tenant, subscriptions[index]);
    return { status: 'verified', message: 'Every explicitly authorized subscription belongs to the intended tenant and is enabled.' };
  } catch (error) {
    return { status: 'mismatch', message: error.message };
  }
}

function validateTarget(target) {
  if (!['cloud', 'local'].includes(target.platform)) throw new Error('Platform must be cloud or local.');
  for (const key of ['context', 'subscription', 'resourceGroup', 'cluster']) {
    if (typeof target[key] !== 'string' || !target[key].trim() || target[key].startsWith('-') || /[\r\n\0]/.test(target[key])) {
      throw new Error(`An explicit, non-option ${key} is required.`);
    }
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(target.subscription)) {
    throw new Error('Use an explicit subscription GUID (from your own az account list).');
  }
}

export async function collect(target, scope, { runner = runCommand, progress = () => {}, now = () => new Date() } = {}) {
  validateTarget(target);
  validateIdentityScope(target, scope);
  const evidence = createEvidence(target, scope, now());
  const needed = requiredSources(scope, target.platform);
  const collectOne = async (id) => {
    if (scope.strategies && !scope.strategies.includes(strategyFor(id, scope))) {
      evidence.sources[id] = { status: 'notCollected', collectedAt: now().toISOString(),
        reason: `Collection strategy ${strategyFor(id, scope)} was not authorized.` };
      return;
    }
    const started = now();
    const record = { status: 'ok', collectedAt: started.toISOString(), durationMs: 0, commands: [] };
    progress(`Collecting ${id}`);
    try {
      record.commands = commandsFor(id, target, scope, evidence.sources.cluster?.data?.id,
        [...(evidence.sources.relatedResources?.data?.items ?? []), ...(evidence.sources.resourceGraph?.data?.items ?? [])]);
      const projected = [];
      for (const command of record.commands) {
        const response = await runner(command.file, command.args);
        const raw = command.format === 'text' ? response.stdout : JSON.parse(response.stdout);
        const part = projectSource(id, raw, target.platform);
        if (command.scopeResourceId) part.items = part.items.map((item) => ({ ...item, queriedResourceId: command.scopeResourceId }));
        if (command.identityResourceId) part.items = part.items.map((item) => ({ ...item, identityResourceId: command.identityResourceId }));
        projected.push(part);
      }
      const data = projected.length === 1 ? projected[0] : { items: projected.flatMap((part) => part.items) };
      if (['defenderAssessments', 'advisorRecommendations', 'policyStates'].includes(id)) {
        if (data.items.some((item) => typeof item.resourceId !== 'string')) throw new Error(`${id} metadata is missing its assessed resource ID.`);
        const permitted = [evidence.sources.cluster.data.id, ...(evidence.sources.cluster.data.linkedResourceIds ?? []),
          ...(scope.relatedResourceIds ?? []), ...(evidence.sources.relatedResources?.data?.items ?? []).map((item) => item.id)]
          .map((value) => value.toLowerCase());
        data.items = data.items.filter((item) => permitted.some((id) =>
          item.resourceId.toLowerCase() === id || item.resourceId.toLowerCase().startsWith(`${id}/`)));
      }
      record.data = scopeProjection(id, data, scope);
    } catch (error) {
      record.status = 'error';
      record.error = commandFailure(error);
      progress(`Collection error [${id}]: ${record.error.code}: ${record.error.message}`);
    }
    record.durationMs = Math.max(0, now() - started);
    evidence.sources[id] = record;
  };
  const blockRemaining = (reason) => {
    for (const id of needed.filter((key) => !evidence.sources[key])) {
      evidence.sources[id] = { status: 'notCollected', collectedAt: now().toISOString(), reason };
    }
  };
  if (target.tenant) {
    await collectOne('accounts');
    const identity = accountBinding(evidence);
    if (identity.status !== 'verified') {
      evidence.target.binding = identity;
      progress(`Collection blocked: ${identity.message}`);
      blockRemaining(identity.message);
      return evidence;
    }
  }
  await collectOne('context');
  await collectOne('cluster');
  const targetBinding = binding(evidence);
  evidence.target.binding = targetBinding;
  if (targetBinding.status === 'mismatch') {
    blockRemaining('Blocked by target mismatch.');
    return evidence;
  }
  if (needed.includes('resourceGraph')) {
    if (!scope.strategies?.includes('resource-graph')) await collectOne('resourceGraph');
    else evidence.sources.resourceGraph = await collectResourceGraph(target, scope, { runner, progress, now });
  }
  if (needed.includes('relatedResources')) {
    if (scope.strategies && !scope.strategies.includes('dependencies')) await collectOne('relatedResources');
    else evidence.sources.relatedResources = await collectRelatedResources(target, scope, evidence.sources.cluster, { runner, progress, now });
  }
  const pending = needed.filter((id) => !['accounts', 'context', 'cluster', 'relatedResources', 'resourceGraph'].includes(id));
  // Small worker pool limits API pressure; one denied resource never becomes an empty successful list.
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(3, pending.length) }, async () => {
    while (next < pending.length) {
      const id = pending[next++];
      if (activeSources.includes(id)) {
        evidence.sources[id] = { status: 'notCollected', collectedAt: now().toISOString(), reason: 'Active tests require separate authorization.' };
      } else await collectOne(id);
    }
  }));
  return evidence;
}

async function collectResourceGraph(target, scope, { runner, progress, now }) {
  const started = now();
  const record = { status: 'ok', collectedAt: started.toISOString(), durationMs: 0, commands: [], data: { items: [] } };
  const tokens = new Set();
  let token;
  try {
    do {
      const base = commandsFor('resourceGraph', target, scope)[0];
      const command = { file: base.file, args: [...base.args, ...(token ? ['--skip-token', token] : [])] };
      record.commands.push(command);
      const response = await runner(command.file, command.args);
      const page = JSON.parse(response.stdout);
      if (!Array.isArray(page?.data)) throw new Error('Resource Graph returned no explicit data array.');
      for (const raw of page.data) {
        try { approvedResourceSubscription(raw.id, scope.authorizedSubscriptions); }
        catch (error) { throw new CommandError('SCOPE_DENIED', error.message); }
        if (record.data.items.length >= (scope.maxInventoryResources ?? 5000)) throw new CommandError('RESOURCE_LIMIT', 'Subscription inventory exceeded maxInventoryResources.');
        record.data.items.push(...projectSource('resourceGraph', [raw]).items);
      }
      token = page.skip_token ?? page.skipToken ?? page.$skipToken;
      if (token !== undefined && token !== null && typeof token !== 'string') throw new Error('Resource Graph returned an invalid pagination token.');
      if (token && tokens.has(token)) throw new CommandError('PAGINATION_LOOP', 'Resource Graph repeated a pagination token.');
      if (token) tokens.add(token);
    } while (token);
  } catch (error) {
    record.status = 'error';
    record.error = commandFailure(error);
    progress(`Collection error [resourceGraph]: ${record.error.code}: ${record.error.message}`);
  }
  record.durationMs = Math.max(0, now() - started);
  return record;
}

async function collectRelatedResources(target, scope, cluster, { runner, progress, now }) {
  const started = now();
  const record = { status: 'ok', collectedAt: started.toISOString(), durationMs: 0, commands: [], data: { items: [] }, failures: [] };
  const pending = [...(scope.relatedResourceIds ?? []), ...(cluster?.data?.linkedResourceIds ?? [])];
  const seen = new Set();
  const maximum = scope.maxRelatedResources ?? 200;
  for (let index = 0; index < pending.length; index++) {
    const id = pending[index];
    if (typeof id === 'string' && seen.has(id.toLowerCase())) continue;
    try {
      let parsed;
      try { parsed = resourceId(id, scope.authorizedSubscriptions ?? [target.subscription.toLowerCase()]); }
      catch (error) { throw new CommandError('SCOPE_DENIED', error.message); }
      if (seen.size >= maximum) throw new CommandError('RESOURCE_LIMIT', `Related resource traversal exceeded the configured ${maximum} resource limit.`);
      seen.add(id.toLowerCase());
      const command = { file: 'az', args: ['resource', 'show', '--subscription', parsed.subscription,
        '--ids', id, '--output', 'json', '--only-show-errors'] };
      record.commands.push(command);
      progress(`Collecting related resource ${id}`);
      const response = await runner(command.file, command.args);
      const projected = projectSource('relatedResources', JSON.parse(response.stdout)).items[0];
      if (projected.id.toLowerCase() !== id.toLowerCase()) throw new Error('Related resource ID does not match the requested resource.');
      record.data.items.push(projected);
      pending.push(...projected.linkedResourceIds);
    } catch (error) {
      const failure = commandFailure(error);
      record.failures.push({ resourceId: id, error: failure });
      progress(`Collection error [relatedResources]: ${failure.code}: ${failure.message}`);
      if (failure.code === 'RESOURCE_LIMIT') break;
    }
  }
  if (record.failures.length) {
    record.status = 'error';
    record.error = record.failures[0].error;
  }
  record.durationMs = Math.max(0, now() - started);
  return record;
}
