import { catalogVersion, catalogDigest, selectControls, severities, statuses, toolVersion } from './catalog.mjs';
import { schemaVersion, validateEvidence } from './evidence.mjs';
import { binding } from './collector.mjs';
import { evaluateRule, manualObservation } from './rules.mjs';
import { inScope, namespacedSources } from './projection.mjs';
import { rating } from './scoring.mjs';

export function summarize(results, bindingStatus) {
  const counts = Object.fromEntries(statuses.map((status) => [status, results.filter((result) => result.status === status).length]));
  const applicable = results.length - counts.notApplicable;
  const evaluated = counts.pass + counts.fail;
  const complete = results.filter((result) => ['pass', 'fail'].includes(result.status) && !result.incomplete).length;
  return {
    total: results.length, applicable, evaluated, counts,
    partial: results.filter((result) => result.incomplete).length,
    alignmentPercent: evaluated && bindingStatus === 'verified' ? Math.round(counts.pass / evaluated * 100) : null,
    evidenceCoveragePercent: applicable ? Math.round(complete / applicable * 100) : null
  };
}

export function assess(input, { categories = input.scope?.categories, now = new Date() } = {}) {
  const evidence = validateEvidence(input);
  const targetBinding = binding(evidence);
  const evaluate = (control, evidence) => {
    const base = { id: control.id, evidence: [], incomplete: false };
    if (!control.platforms.includes(evidence.target.platform)) {
      return { ...base, status: 'notApplicable', message: `Not applicable to ${evidence.target.platform}; cloud and Local controls are not interchangeable.` };
    }
    if (control.productionOnly && evidence.scope.profile !== 'production') {
      return { ...base, status: 'notApplicable', message: 'Production recommendation intentionally excluded by the development profile.' };
    }
    if (targetBinding.status === 'mismatch' && control.id !== 'CP-001') {
      return { ...base, status: 'unknown', message: 'Assessment blocked: context and ARM endpoints differ. Recollect for one verified target.', incomplete: true };
    }
    base.evidence = control.requires.map((sourceId) => {
      const record = evidence.sources[sourceId];
      return {
        sourceId, path: `/sources/${sourceId}/data`, status: record?.status ?? 'missing',
        collectedAt: record?.collectedAt, commands: record?.commands ?? [], error: record?.error
      };
    });
    const missing = control.requires.filter((id) => evidence.sources[id]?.status !== 'ok');
    if (missing.length) {
      const withheld = missing.every((id) => evidence.sources[id]?.status === 'notCollected'
        && /strategy.*not authorized/i.test(evidence.sources[id].reason ?? ''));
      const unrun = withheld || control.mode === 'active' && missing.every((id) => !evidence.sources[id] || evidence.sources[id].status === 'notCollected');
      const pending = evidence.activeRun?.cleanup?.status === 'pending'
        && missing.some((id) => evidence.sources[id]?.runId === evidence.activeRun.runId);
      return {
        ...base, status: unrun ? 'notRun' : control.mode === 'active' ? 'error' : 'unknown',
        message: withheld ? 'Not run: required collection strategies were not authorized. This is an evidence gap, not a pass.'
          : unrun ? pending ? 'Not completed: an authorized run is pending or interrupted; cleanup is unconfirmed.'
          : 'Not run: separate active-test authorization is required.'
          : `Required evidence is unavailable: ${missing.join(', ')}. No successful conclusion is inferred.`,
        incomplete: !unrun
      };
    }
    try {
      const result = control.mode === 'manual' ? manualObservation(control, evidence) : evaluateRule(control.id, evidence);
      if (!statuses.includes(result.status)) throw new Error('Evaluator returned an invalid status.');
      return { ...base, ...result, classification: result.status === 'pass' ? 'adherence' : result.status === 'fail'
        ? control.failureType ?? 'deviation' : result.status === 'review' ? 'requires-context' : 'insufficient-evidence' };
    } catch (error) {
      return { ...base, status: 'error', message: `Evaluation error: ${error.message}`, incomplete: true };
    }
  };
  const evaluateScored = (control, scopedEvidence) => {
    const result = evaluate(control, scopedEvidence);
    return { ...result, score: rating.score(result, targetBinding.status) };
  };
  const results = selectControls(categories).map((control) => evaluateScored(control, evidence));
  const namespaceNames = new Set(evidence.scope.namespaces ?? []);
  for (const item of evidence.sources.namespaces?.data?.items ?? []) {
    if (inScope(item.metadata.name, evidence.scope)) namespaceNames.add(item.metadata.name);
  }
  for (const id of namespacedSources) {
    for (const item of evidence.sources[id]?.data?.items ?? []) {
      if (inScope(item.metadata.namespace, evidence.scope)) namespaceNames.add(item.metadata.namespace);
    }
  }
  const namespaceResults = [...namespaceNames].sort().map((namespace) => {
    const scopedEvidence = { ...evidence, scope: { ...evidence.scope, namespaces: [namespace] } };
    return { namespace, results: rating.namespaceControls(categories).map((control) => evaluateScored(control, scopedEvidence)) };
  });
  return {
    schemaVersion, toolVersion, catalogVersion, catalogDigest, assessedAt: now.toISOString(), collectedAt: evidence.collectedAt,
    synthetic: evidence.synthetic === true, target: { ...evidence.target, binding: targetBinding },
    scope: { ...evidence.scope, categories }, summary: summarize(results, targetBinding.status),
    collection: Object.entries(evidence.sources).map(([sourceId, record]) => ({
      sourceId, status: record.status, collectedAt: record.collectedAt, durationMs: record.durationMs,
      commands: record.commands ?? [], error: record.error, reason: record.reason, failures: record.failures
    })),
    activeRun: evidence.activeRun, results, namespaceResults,
    ratings: rating.build(results, namespaceResults, targetBinding.status, categories)
  };
}

export function exitCode(assessment, failOn = 'none') {
  if (!['none', ...severities].includes(failOn)) throw new Error(`Invalid --fail-on severity: ${failOn}`);
  if (assessment.summary.counts.unknown || assessment.summary.counts.error || assessment.summary.partial
    || assessment.target.binding.status !== 'verified' || assessment.collection.some((record) => record.status === 'error')
    || ['error', 'pending'].includes(assessment.activeRun?.cleanup?.status)) return 2;
  if (failOn === 'none') return 0;
  const threshold = severities.indexOf(failOn);
  const byId = new Map(selectControls(assessment.scope.categories).map((control) => [control.id, control]));
  return assessment.results.some((result) => result.status === 'fail' && severities.indexOf(byId.get(result.id).severity) <= threshold) ? 1 : 0;
}
