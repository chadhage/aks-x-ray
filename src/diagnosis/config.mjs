import { assertKeys } from '../scope.mjs';
import { loadStatistics } from '../rules.mjs';
import { assessmentStrategies, intrusiveSuites, nonMutatingTests, validationStages } from './strategies.mjs';

function selection(value, allowed, label, { empty = false } = {}) {
  if (!Array.isArray(value) || !empty && !value.length || value.some((item) => !allowed.includes(item))) {
    throw new Error(`Invalid ${label}: select ${allowed.join(', ')}.`);
  }
  if (new Set(value).size !== value.length) throw new Error(`Duplicate ${label}.`);
  return [...value];
}

function approval(input = {}, intrusive = false) {
  const label = intrusive ? 'intrusive approval' : 'non-mutating approval';
  assertKeys(input, ['approved', 'contexts', 'namespaces', 'tests', 'suites', 'expiresAt', 'limits'], label);
  for (const key of ['contexts', 'namespaces', 'tests', 'suites', 'limits']) if (input[key] === null) throw new Error(`Invalid ${label} ${key}.`);
  if (input.approved !== undefined && typeof input.approved !== 'boolean') throw new Error(`${label} approved must be a boolean.`);
  const contexts = input.contexts ?? [];
  if (!Array.isArray(contexts) || contexts.some((value) => typeof value !== 'string' || !value.trim() || value.startsWith('-') || /[\r\n\0]/.test(value))
    || new Set(contexts).size !== contexts.length) throw new Error(`Invalid ${label} contexts.`);
  const namespaces = input.namespaces ?? [];
  if (!Array.isArray(namespaces) || namespaces.some((value) => typeof value !== 'string' || value.length > 63 || !/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(value))
    || new Set(namespaces).size !== namespaces.length) throw new Error(`Invalid ${label} namespaces.`);
  const tests = selection(input.tests ?? [], nonMutatingTests, `${label} tests`, { empty: true });
  const suites = selection(input.suites ?? [], intrusiveSuites, `${label} suites`, { empty: true });
  if (intrusive && tests.length || !intrusive && suites.length) throw new Error(`Tests and suites must match the ${label} stage.`);
  const expiresAt = input.expiresAt ?? null;
  if (expiresAt !== null && (typeof expiresAt !== 'string'
    || !/^\d{4}-\d\d-\d\dT(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.test(expiresAt)
    || !Number.isFinite(Date.parse(expiresAt))
    || new Date(`${expiresAt.slice(0, 10)}T00:00:00Z`).toISOString().slice(0, 10) !== expiresAt.slice(0, 10))) {
    throw new Error(`Invalid ${label} expiresAt timestamp.`);
  }
  if (input.approved === true) {
    if (!contexts.length) throw new Error(`${label} requires exact approved contexts.`);
    if (!expiresAt) throw new Error(`${label} requires an expiry.`);
    if (intrusive && !suites.length || !intrusive && !tests.length) throw new Error(`${label} requires explicit tests or suites.`);
    if (!intrusive && tests.some((id) => id !== 'intrusive-preflight') && !namespaces.length) throw new Error(`${label} requires explicit namespaces.`);
  }
  assertKeys(input.limits ?? {}, ['requests', 'concurrency', 'durationSeconds', 'latencyBudgetMs', 'errorBudgetPercent'], `${label} limits`);
  const limits = { requests: 40, concurrency: 2, durationSeconds: 10, latencyBudgetMs: 2000, errorBudgetPercent: 0, ...input.limits };
  loadStatistics({ limits: { requests: limits.requests, concurrency: limits.concurrency, durationSeconds: limits.durationSeconds, workerPacingMs: 100 },
    budgets: { p95Ms: limits.latencyBudgetMs, maxErrorRatePercent: limits.errorBudgetPercent },
    samples: [{ ok: true, latencyMs: 0 }], durationMs: 0 });
  return { approved: input.approved === true, contexts: [...contexts], namespaces: [...namespaces], tests, suites, expiresAt, limits };
}

export function normalizeAssessment(value) {
  assertKeys(value, ['strategies', 'stages', 'approvals', 'maxEvidenceAgeHours', 'maxPaths',
    'maxGraphNodes', 'maxGraphEdges', 'maxInventoryResources', 'maxValidationChecks'], 'assessment');
  if (value.stages === null) throw new Error('Validation stages cannot be null.');
  if (value.approvals === null) throw new Error('Assessment approvals cannot be null.');
  const strategies = selection(value.strategies, assessmentStrategies, 'assessment strategies');
  const stages = selection(value.stages ?? ['passive'], validationStages, 'validation stages');
  if (!stages.includes('passive')) throw new Error('The passive collection stage must be explicitly included.');
  if (!strategies.includes('validation') && stages.some((stage) => stage !== 'passive')) throw new Error('Non-passive stages require the validation strategy.');
  assertKeys(value.approvals ?? {}, ['nonMutating', 'intrusive'], 'assessment approvals');
  const result = {
    strategies, stages,
    approvals: { nonMutating: approval(value.approvals?.nonMutating), intrusive: approval(value.approvals?.intrusive, true) },
    maxEvidenceAgeHours: value.maxEvidenceAgeHours ?? 24,
    maxPaths: value.maxPaths ?? 200, maxGraphNodes: value.maxGraphNodes ?? 20_000, maxGraphEdges: value.maxGraphEdges ?? 50_000,
    maxInventoryResources: value.maxInventoryResources ?? 5000, maxValidationChecks: value.maxValidationChecks ?? 100
  };
  for (const [key, maximum] of [['maxPaths', 10_000], ['maxGraphNodes', 100_000], ['maxGraphEdges', 200_000],
    ['maxInventoryResources', 50_000], ['maxValidationChecks', 1000]]) {
    if (value[key] === null || !Number.isInteger(result[key]) || result[key] < 1 || result[key] > maximum) throw new Error(`${key} must be an integer from 1 to ${maximum}.`);
  }
  if (value.maxEvidenceAgeHours === null || !Number.isFinite(result.maxEvidenceAgeHours) || result.maxEvidenceAgeHours <= 0 || result.maxEvidenceAgeHours > 8760) {
    throw new Error('maxEvidenceAgeHours must be greater than zero and at most 8760.');
  }
  return result;
}

export function assessmentPlan(assessment) {
  return {
    strategies: assessment.strategies, stages: assessment.stages,
    dependencies: ['resource-identity-graph', ...(assessment.strategies.includes('configuration') ? ['configuration-evaluator'] : [])],
    approvalRequirements: assessment.stages.filter((stage) => stage !== 'passive').map((stage) => ({
      stage, ...assessment.approvals[stage === 'non-mutating' ? 'nonMutating' : 'intrusive']
    })),
    permissions: 'Live permission reviews are needed for non-mutating/intrusive execution. An approval is not a permission grant.'
  };
}
