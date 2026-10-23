import { isObject } from './projection.mjs';
import { parseCommandJson, runCommand } from './process.mjs';
import { assessmentStrategies } from './diagnosis/strategies.mjs';

export const collectionStrategies = ['azure', 'kubernetes', 'iam', 'policy', 'defender', 'advisor', 'dependencies', 'resource-graph', 'iam-inventory'];
const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isGuid = (value) => typeof value === 'string' && guid.test(value);

export function assertKeys(value, keys, label) {
  if (!isObject(value)) throw new Error(`${label} must be an object.`);
  for (const key of Object.keys(value)) {
    if (!keys.includes(key)) throw new Error(`Unknown ${label} field: ${key}`);
  }
}

export function subscriptionScope(subscriptions) {
  if (!Array.isArray(subscriptions) || !subscriptions.length || subscriptions.length > 100
    || subscriptions.some((id) => typeof id !== 'string' || !guid.test(id))) {
    throw new Error('Provide 1-100 explicit subscription GUIDs.');
  }
  const normalized = subscriptions.map((id) => id.toLowerCase());
  if (new Set(normalized).size !== normalized.length) throw new Error('Duplicate subscription GUIDs.');
  return normalized;
}

export function azureScope(tenant, subscriptions) {
  if (typeof tenant !== 'string' || !guid.test(tenant)) throw new Error('An explicit tenant GUID is required.');
  return { tenant: tenant.toLowerCase(), subscriptions: subscriptionScope(subscriptions) };
}

export function accountRecord(value, tenant, subscription) {
  if (!isObject(value) || typeof value.id !== 'string' || value.id.toLowerCase() !== subscription
    || typeof value.tenantId !== 'string' || value.tenantId.toLowerCase() !== tenant || value.state !== 'Enabled') {
    throw new Error('Account subscription is unavailable, disabled, or does not belong to the explicitly authorized tenant.');
  }
  return { id: value.id.toLowerCase(), tenantId: value.tenantId.toLowerCase(), state: value.state };
}

export async function verifySubscriptions(input, { runner = runCommand } = {}) {
  const { tenant, subscriptions } = azureScope(input.tenant, input.subscriptions);
  const accounts = [];
  for (const subscription of subscriptions) {
    const response = await runner('az', ['account', 'show', '--subscription', subscription,
      '--query', '{id:id,tenantId:tenantId,state:state}', '--output', 'json', '--only-show-errors']);
    accounts.push(accountRecord(parseCommandJson(response.stdout), tenant, subscription));
  }
  return { tenant, subscriptions: accounts };
}

export function validateIdentityScope(target, scope) {
  if (target.tenant === undefined && scope.strategies === undefined) return;
  const identity = azureScope(target.tenant, scope.authorizedSubscriptions);
  if (!scope.strategies || scope.authorization?.readOnly !== true) throw new Error('A tenant-bound target requires an explicitly authorized collection scope.');
  if (typeof target.subscription !== 'string' || !identity.subscriptions.includes(target.subscription.toLowerCase())) {
    throw new Error('Target is outside the authorized subscriptions.');
  }
}

export function resourceId(value, subscriptions) {
  if (typeof value !== 'string' || !/^\/subscriptions\/[0-9a-f-]+\/resourceGroups\/[a-z0-9_.()-]+\/providers\/[a-z0-9_.-]+(?:\/[a-z0-9_.()-]+\/[a-z0-9_.()-]+)+$/i.test(value)
    || value.split('/').some((part) => part === '.' || part === '..')) throw new Error('An explicit resource-group ARM resource ID is required.');
  const subscription = value.split('/')[2].toLowerCase();
  if (!guid.test(subscription)) throw new Error('Resource ID must contain a subscription GUID.');
  if (subscriptions && !subscriptions.includes(subscription)) throw new Error('Resource ID is outside the authorized subscriptions.');
  return { id: value, subscription };
}

export function approvedResourceSubscription(value, subscriptions) {
  if (typeof value !== 'string' || /[\r\n\0\\?#]/.test(value) || value.split('/').some((part) => part === '.' || part === '..')) {
    throw new Error('Invalid scoped ARM resource ID.');
  }
  const match = /^\/subscriptions\/([^/]+)(?:\/[^/]+)*$/i.exec(value);
  if (!match || !guid.test(match[1]) || !subscriptions.includes(match[1].toLowerCase())) throw new Error('Resource is outside the approved subscriptions.');
  return match[1].toLowerCase();
}

export function strategyFor(id, scope) {
  if (['accounts', 'cluster', 'nodepools', 'diagnostics', 'maintenance'].includes(id)) return 'azure';
  if (id === 'roleAssignments') return scope?.strategies?.includes('iam-inventory') ? 'iam-inventory' : 'iam';
  if (['roleDefinitions', 'federatedCredentials'].includes(id)) return 'iam-inventory';
  if (id === 'resourceGraph') return 'resource-graph';
  if (id === 'policyStates') return 'policy';
  if (['defenderAssessments', 'defenderPricing'].includes(id)) return 'defender';
  if (id === 'advisorRecommendations') return 'advisor';
  if (id === 'relatedResources') return 'dependencies';
  if (id.startsWith('active')) return 'active';
  return 'kubernetes';
}

export function normalizeRiskScenario(value, profile) {
  const result = {
    businessCriticality: value.businessCriticality === undefined ? profile === 'production' ? 'high' : 'medium' : value.businessCriticality,
    dataSensitivity: value.dataSensitivity === undefined ? 'internal' : value.dataSensitivity,
    applicationExposure: value.applicationExposure === undefined ? 'private' : value.applicationExposure,
    assumedCompromise: value.assumedCompromise === undefined ? [] : value.assumedCompromise
  };
  for (const [key, allowed] of [['businessCriticality', ['low', 'medium', 'high', 'critical']],
    ['dataSensitivity', ['public', 'internal', 'confidential', 'restricted']], ['applicationExposure', ['private', 'public', 'mixed']]]) {
    if (!allowed.includes(result[key])) throw new Error(`Invalid scenario ${key}.`);
  }
  if (!Array.isArray(result.assumedCompromise) || result.assumedCompromise.length > 100
    || result.assumedCompromise.some((id) => typeof id !== 'string' || !id.trim() || id.length > 1024 || /[\r\n\0]/.test(id))
    || new Set(result.assumedCompromise).size !== result.assumedCompromise.length) throw new Error('Scenario assumedCompromise must contain unique explicit graph node IDs.');
  return { ...result, assumedCompromise: [...result.assumedCompromise] };
}

export function normalizeScenario(value, profile) {
  const riskFields = ['businessCriticality', 'dataSensitivity', 'applicationExposure', 'assumedCompromise'];
  assertKeys(value, ['name', 'profile', 'apiAccess', 'minimumReplicas', 'minimumZones', 'allowedRegistries', ...riskFields], 'scenario');
  if (['apiAccess', 'minimumReplicas', 'minimumZones', 'allowedRegistries'].some((key) => value[key] === null)) {
    throw new Error('Scenario fields cannot be null; omit optional fields to use documented profile defaults.');
  }
  if (value.profile !== undefined && value.profile !== profile) throw new Error('Scenario profile must match the assessment profile.');
  if (typeof value.name !== 'string' || !value.name.trim() || value.name.length > 128 || /[\r\n\0]/.test(value.name)) {
    throw new Error('Scenario name must be 1-128 characters without control characters.');
  }
  const scenario = {
    name: value.name, profile, apiAccess: value.apiAccess ?? 'either',
    minimumReplicas: value.minimumReplicas ?? (profile === 'production' ? 2 : 1),
    minimumZones: value.minimumZones ?? (profile === 'production' ? 2 : 1),
    allowedRegistries: value.allowedRegistries ?? []
  };
  if (!['private', 'restricted-public', 'either'].includes(scenario.apiAccess)) throw new Error('Scenario apiAccess must be private, restricted-public or either.');
  for (const [key, maximum] of [['minimumReplicas', 100], ['minimumZones', 3]]) {
    if (!Number.isInteger(scenario[key]) || scenario[key] < 1 || scenario[key] > maximum) {
      throw new Error(`Scenario ${key} must be an integer from 1 to ${maximum}.`);
    }
  }
  if (!Array.isArray(scenario.allowedRegistries) || scenario.allowedRegistries.some((name) =>
    typeof name !== 'string' || name.length > 253 || !/^[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?$/.test(name))
    || new Set(scenario.allowedRegistries).size !== scenario.allowedRegistries.length) {
    throw new Error('Scenario allowedRegistries must contain unique lowercase registry hostnames, without paths or credentials.');
  }
  if (riskFields.some((key) => value[key] !== undefined)) Object.assign(scenario, normalizeRiskScenario(value, profile));
  return scenario;
}

export function validateScopeExtensions(scope) {
  if (scope.scenario !== undefined) normalizeScenario(scope.scenario, scope.profile);
  if (scope.assessmentStrategies !== undefined && (!Array.isArray(scope.assessmentStrategies) || !scope.assessmentStrategies.length
    || scope.assessmentStrategies.some((id) => !assessmentStrategies.includes(id))
    || new Set(scope.assessmentStrategies).size !== scope.assessmentStrategies.length)) throw new Error('Invalid assessment strategies in collection scope.');
  if (scope.maxInventoryResources !== undefined && (!Number.isInteger(scope.maxInventoryResources) || scope.maxInventoryResources < 1 || scope.maxInventoryResources > 50_000)) {
    throw new Error('Invalid maxInventoryResources in collection scope.');
  }
  if (scope.strategies === undefined) {
    if (['authorization', 'authorizedSubscriptions', 'relatedResourceIds', 'maxRelatedResources', 'assessmentStrategies', 'maxInventoryResources'].some((key) => scope[key] !== undefined)) {
      throw new Error('Extended collection scope requires explicit strategies.');
    }
    return;
  }
  if (!Array.isArray(scope.strategies) || !scope.strategies.length
    || scope.strategies.some((strategy) => !collectionStrategies.includes(strategy))) throw new Error('Unknown or missing collection strategy.');
  if (new Set(scope.strategies).size !== scope.strategies.length) throw new Error('Duplicate collection strategies.');
  if (!scope.strategies.includes('azure')) throw new Error('The azure strategy is required for tenant and ARM target verification.');
  assertKeys(scope.authorization, ['readOnly'], 'authorization');
  if (scope.authorization.readOnly !== true) throw new Error('Authorization readOnly must be explicitly true.');
  subscriptionScope(scope.authorizedSubscriptions);
  if (!Array.isArray(scope.relatedResourceIds) || scope.relatedResourceIds.length > 1000) throw new Error('relatedResourceIds must be an array of at most 1000 resource IDs.');
  for (const id of scope.relatedResourceIds) resourceId(id, scope.authorizedSubscriptions);
  if (new Set(scope.relatedResourceIds.map((id) => id.toLowerCase())).size !== scope.relatedResourceIds.length) throw new Error('Duplicate related resource IDs.');
  if (scope.relatedResourceIds.length && !scope.strategies.includes('dependencies')) throw new Error('Related resources require the dependencies strategy.');
  if (!Number.isInteger(scope.maxRelatedResources) || scope.maxRelatedResources < 1 || scope.maxRelatedResources > 1000) {
    throw new Error('maxRelatedResources must be an integer from 1 to 1000.');
  }
}
