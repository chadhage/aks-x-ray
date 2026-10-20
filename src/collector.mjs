import { createEvidence } from './evidence.mjs';
import { selectControls } from './catalog.mjs';
import { activeSources, kubernetesResources, namespacedSources, projectSource, scopeProjection } from './projection.mjs';
import { runCommand, commandFailure } from './process.mjs';
import { isIP } from 'node:net';

export function requiredSources(scope, platform) {
  return [...new Set([
    'context', 'cluster',
    ...selectControls(scope.categories).filter((control) => control.platforms.includes(platform)).flatMap((control) => control.requires)
  ])];
}

export function commandsFor(id, target, scope, clusterId) {
  const azureScope = ['--subscription', target.subscription, '--resource-group', target.resourceGroup];
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
  const context = evidence.sources.context;
  const cluster = evidence.sources.cluster;
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
  const evidence = createEvidence(target, scope, now());
  const needed = requiredSources(scope, target.platform);
  const collectOne = async (id) => {
    const started = now();
    const record = { status: 'ok', collectedAt: started.toISOString(), durationMs: 0, commands: [] };
    progress(`Collecting ${id}`);
    try {
      record.commands = commandsFor(id, target, scope, evidence.sources.cluster?.data?.id);
      const projected = [];
      for (const command of record.commands) {
        const response = await runner(command.file, command.args);
        const raw = command.format === 'text' ? response.stdout : JSON.parse(response.stdout);
        projected.push(projectSource(id, raw, target.platform));
      }
      const data = projected.length === 1 ? projected[0] : { items: projected.flatMap((part) => part.items) };
      record.data = scopeProjection(id, data, scope);
    } catch (error) {
      record.status = 'error';
      record.error = commandFailure(error);
      progress(`Collection error [${id}]: ${record.error.code}: ${record.error.message}`);
    }
    record.durationMs = Math.max(0, now() - started);
    evidence.sources[id] = record;
  };
  await collectOne('context');
  await collectOne('cluster');
  const targetBinding = binding(evidence);
  evidence.target.binding = targetBinding;
  if (targetBinding.status === 'mismatch') {
    for (const id of needed.filter((key) => !['context', 'cluster'].includes(key))) {
      evidence.sources[id] = { status: 'notCollected', collectedAt: now().toISOString(), reason: 'Blocked by target mismatch.' };
    }
    return evidence;
  }
  const pending = needed.filter((id) => !['context', 'cluster'].includes(id));
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
