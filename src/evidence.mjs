import { categories, selectControls, toolVersion, catalogVersion, catalogDigest } from './catalog.mjs';
import { activeSources, isObject, kubernetesResources, namespacedSources, sourceIds, workloadSources } from './projection.mjs';

export const schemaVersion = '1.0';
export const systemNamespaces = ['kube-system', 'kube-public', 'kube-node-lease'];
const validNamespace = (value) => typeof value === 'string' && /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(value) && value.length <= 63;

export function validateScope(scope) {
  if (!isObject(scope) || !Array.isArray(scope.categories) || !scope.categories.length) throw new Error('Scope must select categories.');
  selectControls(scope.categories);
  if (new Set(scope.categories).size !== scope.categories.length) throw new Error('Duplicate categories in scope.');
  if (!['production', 'development'].includes(scope.profile)) throw new Error('Profile must be production or development.');
  for (const key of ['namespaces', 'excludedNamespaces']) {
    if (key === 'namespaces' && scope[key] === null) continue;
    if (!Array.isArray(scope[key]) || scope[key].some((value) => !validNamespace(value))) throw new Error(`Invalid ${key} scope.`);
    if (new Set(scope[key]).size !== scope[key].length) throw new Error(`Duplicate ${key} scope.`);
  }
  if (scope.namespaces?.length === 0) throw new Error('An explicit namespace scope cannot be empty.');
  if (scope.namespaces?.some((value) => scope.excludedNamespaces.includes(value))) {
    throw new Error('An explicitly selected namespace is excluded. Use --include-system if you intend to assess system namespaces.');
  }
}

export function createEvidence(target, scope, now = new Date()) {
  validateScope(scope);
  return {
    schemaVersion, toolVersion, catalogVersion, catalogDigest, collectedAt: now.toISOString(),
    synthetic: false, target: { ...target }, scope: structuredClone(scope), sources: {}
  };
}

function validateData(id, data) {
  if (!isObject(data)) throw new Error(`Source ${id} requires an object data payload.`);
  if (id === 'context') {
    const url = new URL(data.server);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error('Invalid context server.');
  } else if (id === 'cluster') {
    if (typeof data.name !== 'string' || typeof data.id !== 'string') throw new Error('Cluster metadata needs name and id.');
  } else if (!activeSources.includes(id)) {
    if (!Array.isArray(data.items)) throw new Error(`Source ${id} is missing its items array.`);
    for (const item of data.items) {
      if (!isObject(item)) throw new Error(`Invalid item in ${id}.`);
      if (id in kubernetesResources && typeof item.metadata?.name !== 'string') throw new Error(`Invalid resource metadata in ${id}.`);
      if (namespacedSources.has(id) && !validNamespace(item.metadata.namespace)) throw new Error(`Invalid namespace in ${id}.`);
      if (workloadSources.includes(id)) {
        if (!isObject(item.pod?.spec) || !Array.isArray(item.pod.spec.containers) || !item.pod.spec.containers.length) {
          throw new Error(`Invalid pod specification in ${id}.`);
        }
      }
    }
  }
}

export function validateEvidence(value) {
  if (!isObject(value) || value.schemaVersion !== schemaVersion) throw new Error(`Evidence schemaVersion must be ${schemaVersion}.`);
  if (value.catalogVersion !== catalogVersion) throw new Error(`Evidence needs catalogVersion ${catalogVersion}; use the matching repository revision.`);
  if (value.catalogDigest !== catalogDigest) throw new Error('Evidence catalogue digest differs; assess with the matching repository revision.');
  if (typeof value.synthetic !== 'boolean' || typeof value.toolVersion !== 'string') throw new Error('Evidence must declare its tool version and synthetic flag.');
  if (!isObject(value.target) || !['cloud', 'local'].includes(value.target.platform)
    || typeof value.target.context !== 'string' || !value.target.context.trim()
    || value.target.context.startsWith('-') || /[\r\n\0]/.test(value.target.context)) throw new Error('An explicit platform and Kubernetes context are required.');
  for (const key of ['subscription', 'resourceGroup', 'cluster']) {
    if (typeof value.target[key] !== 'string' || !value.target[key]) throw new Error(`Evidence target.${key} is required.`);
  }
  if (!Number.isFinite(Date.parse(value.collectedAt))) throw new Error('Invalid collection timestamp.');
  validateScope(value.scope);
  if (!isObject(value.sources)) throw new Error('Evidence sources must be an object.');
  for (const [id, record] of Object.entries(value.sources)) {
    if (!sourceIds.includes(id)) throw new Error(`Unknown evidence source: ${id}`);
    if (!isObject(record) || !['ok', 'error', 'notCollected', 'notApplicable'].includes(record.status)) {
      throw new Error(`Invalid collection status for ${id}.`);
    }
    if (!Number.isFinite(Date.parse(record.collectedAt))) throw new Error(`Invalid timestamp for ${id}.`);
    if (record.status === 'ok') validateData(id, record.data);
    if (record.status === 'error' && (!isObject(record.error) || typeof record.error.message !== 'string')) {
      throw new Error(`Source ${id} is missing an explicit error.`);
    }
    if (record.commands !== undefined && (!Array.isArray(record.commands) || record.commands.some((command) =>
      !isObject(command) || !['az', 'kubectl'].includes(command.file) || !Array.isArray(command.args)
      || command.args.some((argument) => typeof argument !== 'string')))) throw new Error(`Invalid recorded commands for ${id}.`);
  }
  return value;
}

export function defaultScope(options = {}) {
  const scope = {
    categories: options.categories ?? categories.map(({ id }) => id),
    namespaces: options.namespaces ?? null,
    excludedNamespaces: options.includeSystem ? [] : [...systemNamespaces],
    profile: options.profile ?? 'production'
  };
  validateScope(scope);
  return scope;
}
