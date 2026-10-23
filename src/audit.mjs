import { defaultScope } from './evidence.mjs';
import { collect, requiredSources } from './collector.mjs';
import { assertKeys, azureScope, resourceId, strategyFor, verifySubscriptions } from './scope.mjs';
import { isObject } from './projection.mjs';
import { parseCommandJson, runCommand } from './process.mjs';
import { assess, exitCode } from './engine.mjs';
import { prepareOutput, writeArtifacts, writeAuditIndex } from './report.mjs';
import { join } from 'node:path';
import { catalogVersion, catalogDigest } from './catalog.mjs';
import { assessmentPlan, normalizeAssessment } from './diagnosis/config.mjs';

export const targetSelectionModes = ['named', 'default-subscription-only', 'all-accessible-clusters'];

export function applyRuntimeParameters(config, overlay = {}) {
  if (!isObject(config)) throw new Error('Audit config must be an object.');
  if (!isObject(overlay)) throw new Error('Runtime parameters must be an object.');
  const next = { ...config };
  if (overlay.tenant !== undefined) next.tenant = overlay.tenant;
  if (overlay.subscriptions !== undefined) next.subscriptions = overlay.subscriptions;
  if (overlay.targetSelection !== undefined) next.targetSelection = overlay.targetSelection;
  return next;
}

export function targetSelectionMode(input) {
  const mode = input.targetSelection === undefined ? 'named' : input.targetSelection;
  if (!targetSelectionModes.includes(mode)) {
    throw new Error('targetSelection must be named, default-subscription-only or all-accessible-clusters.');
  }
  if (mode === 'default-subscription-only' && (!Array.isArray(input.subscriptions) || input.subscriptions.length !== 1)) {
    throw new Error('default-subscription-only requires exactly one authorized subscription GUID.');
  }
  return mode;
}

function targetKey(target) {
  return `${target.platform}/${target.subscription}/${target.resourceGroup}/${target.cluster}`.toLowerCase();
}

function normalizeTargets(input, identity, scope) {
  const mode = targetSelectionMode(input);
  const explicit = input.targets === undefined ? [] : input.targets;
  if (!Array.isArray(explicit) || explicit.length > 100) throw new Error('Provide at most 100 AKS targets.');
  if (mode === 'named' && !explicit.length) throw new Error('Named target selection requires 1-100 explicit AKS targets.');
  const kubernetes = scope.strategies.includes('kubernetes');
  if (mode !== 'named' && kubernetes && !explicit.length) {
    throw new Error('Discovery target selection cannot use the kubernetes strategy without explicit per-cluster context mappings.');
  }
  const seen = new Set();
  const contexts = new Set();
  return explicit.map((target) => {
    assertKeys(target, ['platform', 'subscription', 'resourceGroup', 'cluster', 'context'], 'target');
    if (!['cloud', 'local'].includes(target.platform)) throw new Error('Target platform must be cloud or local.');
    if (typeof target.subscription !== 'string' || !identity.subscriptions.includes(target.subscription.toLowerCase())) {
      throw new Error('Every target must belong to an authorized subscription.');
    }
    if (mode === 'default-subscription-only' && target.subscription.toLowerCase() !== identity.subscriptions[0]) {
      throw new Error('default-subscription-only targets must use the single authorized subscription.');
    }
    if (typeof target.resourceGroup !== 'string' || !/^[a-z0-9_().-]{1,90}$/i.test(target.resourceGroup)) throw new Error('Invalid target resourceGroup.');
    if (typeof target.cluster !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,62}$/i.test(target.cluster)) throw new Error('Invalid target cluster name.');
    if (kubernetes || target.context !== undefined) {
      if (typeof target.context !== 'string' || !target.context.trim() || target.context.startsWith('-') || /[\r\n\0]/.test(target.context)) {
        throw new Error('An explicit non-option Kubernetes context is required.');
      }
    }
    const key = targetKey(target);
    if (seen.has(key)) throw new Error('Duplicate audit target.');
    if (target.context !== undefined && contexts.has(target.context) && kubernetes) {
      throw new Error('Do not reuse a Kubernetes context for different audit targets.');
    }
    seen.add(key);
    if (target.context !== undefined) contexts.add(target.context);
    return { ...target, subscription: target.subscription.toLowerCase(), tenant: identity.tenant };
  });
}

export function validateAuditConfig(input) {
  assertKeys(input, ['$schema', 'tenant', 'subscriptions', 'authorization', 'strategies', 'scenario', 'targets',
    'targetSelection', 'categories', 'namespaces', 'includeSystem', 'relatedResourceIds', 'maxRelatedResources', 'assessment'], 'config');
  if (input.$schema !== undefined && typeof input.$schema !== 'string') throw new Error('Config $schema must be a string.');
  for (const key of ['categories', 'relatedResourceIds']) {
    if (input[key] !== undefined && !Array.isArray(input[key])) throw new Error(`Config ${key} must be an array.`);
  }
  if (input.maxRelatedResources !== undefined && !Number.isInteger(input.maxRelatedResources)) throw new Error('Config maxRelatedResources must be an integer.');
  const identity = azureScope(input.tenant, input.subscriptions);
  assertKeys(input.authorization, ['readOnly'], 'authorization');
  if (input.authorization.readOnly !== true) throw new Error('Authorization readOnly must be explicitly true.');
  if (!isObject(input.scenario) || !['production', 'development'].includes(input.scenario.profile)) {
    throw new Error('Scenario must explicitly select a production or development profile.');
  }
  if (input.includeSystem !== undefined && typeof input.includeSystem !== 'boolean') throw new Error('includeSystem must be a boolean.');
  const assessment = input.assessment === undefined ? undefined : normalizeAssessment(input.assessment);
  const scope = defaultScope({
    categories: input.categories, namespaces: input.namespaces, includeSystem: input.includeSystem,
    profile: input.scenario.profile, scenario: input.scenario,
    strategies: input.strategies, authorization: input.authorization,
    authorizedSubscriptions: identity.subscriptions, relatedResourceIds: input.relatedResourceIds ?? [],
    maxRelatedResources: input.maxRelatedResources ?? 200,
    assessmentStrategies: assessment?.strategies, maxInventoryResources: assessment?.maxInventoryResources
  });
  const targetSelection = targetSelectionMode(input);
  const targets = normalizeTargets(input, identity, scope);
  return { ...identity, targetSelection, scope, targets, ...(assessment ? { assessment } : {}) };
}

export function buildAuditPlan(input) {
  const config = validateAuditConfig(input);
  const discoveryPending = config.targetSelection !== 'named' && !config.targets.length;
  return {
    tenant: config.tenant, subscriptions: config.subscriptions, targetSelection: config.targetSelection,
    readOnly: !config.assessment?.stages.includes('intrusive'), scope: config.scope,
    ...(config.assessment ? { assessment: assessmentPlan(config.assessment) } : {}),
    authentication: 'Run login separately using Azure CLI device-code authentication. Audit never signs in implicitly.',
    targets: config.targets.map((target) => ({
      ...target,
      sources: [...new Set(['accounts', ...requiredSources(config.scope, target.platform)])].map((id) => ({
        id, strategy: strategyFor(id, config.scope), authorized: config.scope.strategies.includes(strategyFor(id, config.scope))
      }))
    })),
    limitations: [config.assessment
      ? 'No secret values, credential harvesting, arbitrary workloads or unapproved validation. Only separately approved stages may run.'
      : 'No secret values, exploitation, resource changes, application logs or active tests.',
      'Related resource references are resolved at collection time, within the authorized subscriptions and configured resource limit.',
      ...(discoveryPending
        ? ['Discovery target selection resolves clusters at collection time with subscription-scoped az aks list. Dry-run does not inventory clusters.']
        : [])]
  };
}

export { verifySubscriptions };

export async function deviceLogin(input, { runner = runCommand } = {}) {
  const identity = azureScope(input.tenant, input.subscriptions);
  await runner('az', ['login', '--tenant', identity.tenant, '--use-device-code', '--output', 'none'], {
    interactive: true, timeoutMs: 600_000, env: { AZURE_CORE_LOGIN_EXPERIENCE_V2: 'off' }
  });
  return verifySubscriptions(identity, { runner });
}

export async function discoverClusters(input, { runner = runCommand } = {}) {
  if (input.authorizeReadOnly !== true) throw new Error('Discovery requires explicit read-only authorization.');
  const verified = await verifySubscriptions(input, { runner });
  const clusters = [];
  for (const account of verified.subscriptions) {
    const response = await runner('az', ['aks', 'list', '--subscription', account.id,
      '--query', '[].{id:id,name:name,resourceGroup:resourceGroup,location:location}', '--output', 'json', '--only-show-errors']);
    const values = parseCommandJson(response.stdout);
    if (!Array.isArray(values)) throw new Error('AKS discovery must return an explicit inventory list.');
    for (const value of values) {
      if (!isObject(value) || typeof value.name !== 'string' || typeof value.resourceGroup !== 'string') throw new Error('Invalid AKS discovery target.');
      resourceId(value.id, [account.id]);
      const expected = `/subscriptions/${account.id}/resourceGroups/${value.resourceGroup}/providers/Microsoft.ContainerService/managedClusters/${value.name}`;
      if (value.id.toLowerCase() !== expected.toLowerCase()) throw new Error('Discovered AKS resource ID does not match its subscription and named target.');
      clusters.push({ id: value.id, subscription: account.id, resourceGroup: value.resourceGroup,
        cluster: value.name, ...(typeof value.location === 'string' ? { location: value.location } : {}) });
    }
  }
  return { tenant: verified.tenant, subscriptions: verified.subscriptions, clusters };
}

export async function resolveAuditTargets(input, { runner = runCommand } = {}) {
  const preview = validateAuditConfig(input);
  if (preview.targetSelection === 'named') return input;
  const discovered = await discoverClusters({
    tenant: preview.tenant, subscriptions: preview.subscriptions, authorizeReadOnly: true
  }, { runner });
  let clusters = discovered.clusters;
  if (preview.targetSelection === 'default-subscription-only') {
    clusters = clusters.filter((cluster) => cluster.subscription === preview.subscriptions[0]);
  }
  if (!clusters.length) throw new Error('No AKS clusters were discovered in the authorized subscriptions.');
  const mappings = new Map(preview.targets.map((target) => [targetKey(target), target]));
  const kubernetes = preview.scope.strategies.includes('kubernetes');
  const targets = clusters.map((cluster) => {
    const mapped = mappings.get(targetKey({
      platform: 'cloud', subscription: cluster.subscription, resourceGroup: cluster.resourceGroup, cluster: cluster.cluster
    }));
    if (kubernetes && typeof mapped?.context !== 'string') {
      throw new Error(`kubernetes strategy requires an explicit context mapping for ${cluster.cluster}.`);
    }
    if (mapped) {
      return {
        platform: mapped.platform, subscription: cluster.subscription, resourceGroup: cluster.resourceGroup,
        cluster: cluster.cluster, ...(mapped.context !== undefined ? { context: mapped.context } : {})
      };
    }
    return { platform: 'cloud', subscription: cluster.subscription, resourceGroup: cluster.resourceGroup, cluster: cluster.cluster };
  });
  for (const target of preview.targets) {
    if (!mappings.size || !clusters.some((cluster) => targetKey({
      platform: target.platform, subscription: cluster.subscription, resourceGroup: cluster.resourceGroup, cluster: cluster.cluster
    }) === targetKey(target))) {
      throw new Error('Context mapping does not match a discovered AKS cluster.');
    }
  }
  return { ...input, targetSelection: preview.targetSelection, targets };
}

export async function runAudit(input, { output, runner = runCommand, log = console.log, error = console.error,
  now = () => new Date(), failOn = 'none', signal, configurationEvaluator } = {}) {
  const config = validateAuditConfig(await resolveAuditTargets(input, { runner }));
  if (!['none', 'high', 'medium', 'low', 'info'].includes(failOn)) throw new Error('Invalid --fail-on severity.');
  if (config.assessment) {
    const { runDiagnosisAudit } = await import('./diagnosis/audit.mjs');
    return runDiagnosisAudit(config, { output, runner, log, error, now, failOn, signal, configurationEvaluator });
  }
  const directory = await prepareOutput(output);
  log(`Output: ${directory}`);
  const runs = [];
  for (const [index, target] of config.targets.entries()) {
    const name = `cluster-${String(index + 1).padStart(3, '0')}`;
    const child = await prepareOutput(join(directory, name));
    const evidence = await collect(target, config.scope, { runner, now, progress: error });
    const assessment = assess(evidence, { now: now() });
    await writeArtifacts(child, { evidence, assessment });
    runs.push({ target: assessment.target, directory: name, summary: assessment.summary,
      rating: assessment.ratings.overall, code: exitCode(assessment, failOn) });
    log(`${name}: ${target.cluster}; binding ${assessment.target.binding.status}; ${assessment.results.length} controls.`);
  }
  const code = Math.max(...runs.map((run) => run.code));
  const index = { schemaVersion: '1.0', catalogVersion, catalogDigest, assessedAt: now().toISOString(),
    tenant: config.tenant, subscriptions: config.subscriptions, scope: config.scope, code, runs };
  await writeAuditIndex(directory, index);
  log(`Audit index: ${join(directory, 'audit.md')}`);
  return { code, directory, runs };
}
