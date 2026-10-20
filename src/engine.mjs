import { catalogVersion, catalogDigest, selectControls, severities, statuses, toolVersion } from './catalog.mjs';
import { schemaVersion, validateEvidence } from './evidence.mjs';
import { binding } from './collector.mjs';
import { evaluateRule, manualObservation } from './rules.mjs';

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
  const results = selectControls(categories).map((control) => {
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
      const unrun = control.mode === 'active' && missing.every((id) => !evidence.sources[id] || evidence.sources[id].status === 'notCollected');
      const pending = evidence.activeRun?.cleanup?.status === 'pending'
        && missing.some((id) => evidence.sources[id]?.runId === evidence.activeRun.runId);
      return {
        ...base, status: unrun ? 'notRun' : control.mode === 'active' ? 'error' : 'unknown',
        message: unrun ? pending ? 'Not completed: an authorized run is pending or interrupted; cleanup is unconfirmed.'
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
  });
  return {
    schemaVersion, toolVersion, catalogVersion, catalogDigest, assessedAt: now.toISOString(), collectedAt: evidence.collectedAt,
    synthetic: evidence.synthetic === true, target: { ...evidence.target, binding: targetBinding },
    scope: { ...evidence.scope, categories }, summary: summarize(results, targetBinding.status),
    collection: Object.entries(evidence.sources).map(([sourceId, record]) => ({
      sourceId, status: record.status, collectedAt: record.collectedAt, durationMs: record.durationMs,
      commands: record.commands ?? [], error: record.error, reason: record.reason
    })),
    activeRun: evidence.activeRun, results
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
