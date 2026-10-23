import { isDeepStrictEqual } from 'node:util';
import { toolVersion } from '../catalog.mjs';
import { normalizeRiskScenario, normalizeScenario } from '../scope.mjs';
import { analyzeAttackPaths, analyzeExposures } from './analysis.mjs';
import { normalizeAssessment } from './config.mjs';
import { configurationClaims, evaluateConfiguration } from './configuration.mjs';
import { buildGraph, GraphLimitError, validateGraph } from './graph.mjs';
import { planAssessment } from './planner.mjs';
import { reconcile } from './reconcile.mjs';
import { attachValidationEvidence, validationClaims } from './validation.mjs';

function evaluate(graph, assessment, scenario, reports, validations, now) {
  const claims = [];
  const gaps = [...graph.gaps];
  const strategyResults = [];
  const limited = graph.gaps.some((gap) => gap.code === 'GRAPH_LIMIT');
  for (const id of assessment.strategies) {
    let result = { claims: [], gaps: [] };
    if (!limited) {
      if (id === 'exposure') result = analyzeExposures(graph, { scenario });
      if (id === 'attack-paths') result = analyzeAttackPaths(graph, { scenario, maxPaths: assessment.maxPaths });
      if (id === 'configuration') result = configurationClaims(graph, reports);
      if (id === 'validation') result = validationClaims(graph, validations, { now, maxEvidenceAgeHours: assessment.maxEvidenceAgeHours });
    }
    claims.push(...result.claims);
    gaps.push(...result.gaps);
    strategyResults.push({ id, status: limited ? 'blocked' : 'completed', claimIds: [...new Set(result.claims.map((claim) => claim.id))].sort(),
      limitations: limited ? ['Graph size limit prevents a complete strategy evaluation.'] : [] });
  }
  const combined = reconcile(claims, { graph, scenario, validations, now, maxEvidenceAgeHours: assessment.maxEvidenceAgeHours });
  return { ...combined, strategyResults, gaps };
}

function validationShape(records, graph) {
  if (!Array.isArray(records) || records.length > 10_000 || new Set(records.map((record) => record.id)).size !== records.length) throw new Error('Diagnosis validation records are invalid or duplicated.');
  for (const record of records) {
    if (typeof record.id !== 'string' || !['completed', 'error', 'blocked', 'pending'].includes(record.status)
      || !Number.isFinite(Date.parse(record.completedAt)) || typeof record.context !== 'string'
      || !graph.scope.clusters.includes(record.clusterId?.toLowerCase())) throw new Error('Diagnosis validation provenance is invalid.');
    if (record.status === 'completed' && record.testId !== 'intrusive-preflight'
      && (typeof record.subject !== 'string' || typeof record.predicate !== 'string' || typeof record.value !== 'boolean')) throw new Error('Completed validation has no explicit semantic result.');
  }
}

function coverage(graph, validations) {
  const sources = graph.sources.filter((source) => source.required);
  return {
    sources: { total: sources.length, available: sources.filter((source) => source.status === 'ok').length,
      unavailable: sources.filter((source) => source.status !== 'ok').length },
    validations: { completed: validations.filter((record) => record.status === 'completed').length,
      errors: validations.filter((record) => record.status === 'error').length,
      blocked: validations.filter((record) => record.status === 'blocked').length },
    graph: { nodes: graph.nodes.length, edges: graph.edges.length, gaps: graph.gaps.length }
  };
}

export function diagnose(bundles, {
  assessment: inputAssessment = { strategies: ['graph', 'exposure', 'attack-paths'], stages: ['passive'] },
  tenant, subscriptions, scenario: inputScenario, validations = [], now = new Date(), configurationEvaluator
} = {}) {
  const assessment = normalizeAssessment(inputAssessment);
  const scopeScenario = inputScenario ?? bundles[0]?.scope?.scenario ?? {};
  const profile = scopeScenario.profile ?? bundles[0]?.scope?.profile ?? 'production';
  const scenario = { ...normalizeScenario({ name: 'Unspecified workload scenario', ...scopeScenario }, profile),
    ...normalizeRiskScenario(scopeScenario, profile) };
  let graph;
  try {
    graph = buildGraph(bundles, { tenant, subscriptions, now, strategies: assessment.strategies,
      maxNodes: assessment.maxGraphNodes, maxEdges: assessment.maxGraphEdges });
  } catch (error) {
    if (!(error instanceof GraphLimitError)) throw error;
    graph = error.graph;
  }
  const orderedValidations = [...validations].sort((a, b) => a.id.localeCompare(b.id, 'en'));
  validationShape(orderedValidations, graph);
  if (assessment.strategies.includes('validation') && !graph.gaps.some((gap) => gap.code === 'GRAPH_LIMIT')) {
    try {
      graph = attachValidationEvidence(graph, orderedValidations, { now, maxEvidenceAgeHours: assessment.maxEvidenceAgeHours,
        maxNodes: assessment.maxGraphNodes, maxEdges: assessment.maxGraphEdges });
    } catch (error) {
      if (!(error instanceof GraphLimitError)) throw error;
      graph = error.graph;
    }
  }
  const configurationAssessments = assessment.strategies.includes('configuration') && !graph.gaps.some((gap) => gap.code === 'GRAPH_LIMIT')
    ? evaluateConfiguration(bundles, { evaluator: configurationEvaluator, now }) : [];
  const result = evaluate(graph, assessment, scenario, configurationAssessments, orderedValidations, now);
  return {
    schemaVersion: '2.0', kind: 'aks-xray-diagnosis', toolVersion, assessedAt: now.toISOString(), synthetic: graph.synthetic,
    selection: { strategies: assessment.strategies, stages: assessment.stages }, assessment, scenario,
    graph, plan: planAssessment(bundles, assessment, { now, records: orderedValidations }),
    validationRecords: orderedValidations, configurationAssessments,
    ...result, coverage: coverage(graph, orderedValidations),
    methodology: {
      risk: 'Project-defined 1-100 review priority; higher is worse. Impact and feasibility reflect this scenario, not a CVSS or probability.',
      confidence: 'Confidence in the stated finding, not assurance that the workload is secure. Low confidence does not discount risk.',
      tiers: ['configured-exposure', 'plausible-exploitability', 'validated-behavior'],
      scope: 'Validation establishes only its exact method, subject, condition, context, namespace and timestamp. It does not validate a whole attack path.'
    }
  };
}

export function validateDiagnosis(value) {
  if (value?.schemaVersion !== '2.0' || value.kind !== 'aks-xray-diagnosis' || !Number.isFinite(Date.parse(value.assessedAt))
    || typeof value.synthetic !== 'boolean') throw new Error('Diagnosis format or provenance is invalid.');
  validateGraph(value.graph);
  if (value.synthetic !== value.graph.synthetic) throw new Error('Diagnosis synthetic provenance differs from its graph.');
  const assessment = normalizeAssessment(value.assessment);
  if (value.graph.nodes.length > assessment.maxGraphNodes || value.graph.edges.length > assessment.maxGraphEdges) throw new Error('Diagnosis graph exceeds the declared limits.');
  if (!isDeepStrictEqual(value.selection, { strategies: assessment.strategies, stages: assessment.stages })) throw new Error('Diagnosis strategy selection differs.');
  validationShape(value.validationRecords, value.graph);
  if (!Array.isArray(value.configurationAssessments) || !assessment.strategies.includes('configuration') && value.configurationAssessments.length) throw new Error('Diagnosis includes an unselected configuration strategy.');
  const expected = evaluate(value.graph, assessment, value.scenario, value.configurationAssessments, value.validationRecords, new Date(value.assessedAt));
  for (const key of ['findings', 'summary', 'views', 'strategyResults', 'gaps']) {
    if (!isDeepStrictEqual(value[key], expected[key])) throw new Error(`Diagnosis ${key} does not match recomputed risk, confidence, tiers and views.`);
  }
  if (!isDeepStrictEqual(value.coverage, coverage(value.graph, value.validationRecords))) throw new Error('Diagnosis coverage does not match its evidence.');
  return value;
}

export function diagnosisExitCode(value, failOn = 'none') {
  if (!['none', 'high', 'medium', 'low', 'info'].includes(failOn)) throw new Error('Invalid --fail-on severity.');
  if (value.gaps.some((gap) => ['GRAPH_LIMIT', 'PATH_LIMIT', 'TARGET_BINDING'].includes(gap.code) || gap.status === 'error' || gap.status === 'missing')
    || value.validationRecords.some((record) => ['error', 'blocked', 'pending'].includes(record.status))
    || value.plan.actions.some((action) => action.stage !== 'passive' && action.status === 'blocked')) return 2;
  const thresholds = { high: 70, medium: 40, low: 15, info: 1 };
  return failOn !== 'none' && value.findings.some((finding) => finding.risk.score !== null && finding.risk.score >= thresholds[failOn]) ? 1 : 0;
}
