import test from 'node:test';
import assert from 'node:assert/strict';
import { buildGraph, kubeId } from '../src/diagnosis/graph.mjs';
import { diagnosisEvidence, diagnosisSubscriptions, diagnosisTenant, diagnosisTimestamp } from '../examples/diagnosis-fixture.mjs';

const reconcileModule = () => import('../src/diagnosis/reconcile.mjs');
function fixture() {
  const evidence = diagnosisEvidence();
  const cluster = evidence.sources.cluster.data.id.toLowerCase();
  const graph = buildGraph([evidence], { tenant: diagnosisTenant, subscriptions: diagnosisSubscriptions });
  const source = graph.sources.find((item) => item.sourceId === 'pods');
  const subject = kubeId(cluster, 'Pod', 'payments', 'checkout-example');
  const claim = (overrides = {}) => ({
    strategy: 'exposure', subject, predicate: 'container-privileged',
    scope: { clusterIds: [cluster], namespace: 'payments', resourceId: null },
    title: 'Privileged container configuration', description: 'Observed configuration, not a runtime escape.',
    stance: 'supports', tier: 'configured-exposure', area: 'security',
    baseImpact: 80, baseConfidence: 85, evidenceRefs: [source.id], validationIds: [], limitations: [],
    ...overrides
  });
  const settings = { graph, scenario: { businessCriticality: 'high', dataSensitivity: 'confidential', applicationExposure: 'public', assumedCompromise: [] },
    now: new Date(diagnosisTimestamp), maxEvidenceAgeHours: 24, validations: [] };
  return { evidence, graph, cluster, subject, claim, settings };
}

test('reconciliation deduplicates the same scoped assertion across strategies and retains every contribution', async () => {
  const { reconcile } = await reconcileModule();
  const { claim, settings } = fixture();
  const result = reconcile([claim(), claim({ strategy: 'configuration' })], settings);
  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0].strategies, ['configuration', 'exposure']);
  assert.equal(result.findings[0].contributions.length, 2);
  assert.equal(result.findings[0].status, 'observed');
});

test('contradictory claims are conflicts, not confidence voting or last-write-wins results', async () => {
  const { reconcile } = await reconcileModule();
  const { claim, settings } = fixture();
  const result = reconcile([claim(), claim({ strategy: 'configuration', stance: 'refutes', baseConfidence: 99 })], settings);
  assert.equal(result.findings[0].status, 'conflicting');
  assert.equal(result.findings[0].contributions.length, 2);
  assert.ok(result.findings[0].risk.score > 0);
  assert.ok(result.findings[0].confidence.limitations.some((item) => /conflict/i.test(item)));
});

test('scope identity prevents same-named workloads in different clusters or namespaces from being merged', async () => {
  const { reconcile } = await reconcileModule();
  const { claim, settings } = fixture();
  const result = reconcile([claim(), claim({ subject: `${claim().subject}-different`, scope: { ...claim().scope, namespace: 'orders' } })], settings);
  assert.equal(result.findings.length, 2);
});

test('risk reflects business criticality and data sensitivity independently of confidence', async () => {
  const { reconcile } = await reconcileModule();
  const { claim, settings } = fixture();
  const low = reconcile([claim()], { ...settings, scenario: { ...settings.scenario, businessCriticality: 'low', dataSensitivity: 'public' } }).findings[0];
  const high = reconcile([claim()], { ...settings, scenario: { ...settings.scenario, businessCriticality: 'critical', dataSensitivity: 'restricted' } }).findings[0];
  assert.ok(high.risk.score > low.risk.score);
  assert.equal(high.confidence.score, low.confidence.score);
  const uncertain = reconcile([claim({ baseConfidence: 20 })], settings).findings[0];
  assert.equal(uncertain.risk.score, reconcile([claim()], settings).findings[0].risk.score);
  assert.ok(uncertain.confidence.score < low.confidence.score);
});

test('missing or refuted evidence is unscored risk, not a zero-risk or healthy conclusion', async () => {
  const { reconcile } = await reconcileModule();
  const { claim, settings } = fixture();
  assert.equal(reconcile([], settings).summary.highestRisk, null);
  assert.equal(reconcile([claim({ stance: 'inconclusive', evidenceRefs: [] })], settings).findings[0].risk.score, null);
  assert.equal(reconcile([claim({ stance: 'refutes' })], settings).findings[0].risk.score, null);
});

test('a validation label alone cannot promote a static claim to validated behavior', async () => {
  const { reconcile } = await reconcileModule();
  const { claim, settings } = fixture();
  const finding = reconcile([claim({ tier: 'validated-behavior' })], settings).findings[0];
  assert.equal(finding.evidenceTier, 'configured-exposure');
  assert.ok(finding.confidence.limitations.some((item) => /validation/i.test(item)));
});

test('validation receipts must match the exact subject, condition, context, namespace and target', async () => {
  const { reconcile } = await reconcileModule();
  const { claim, settings, evidence, cluster } = fixture();
  const subject = kubeId(cluster, 'Identity-User', undefined, 'auditor');
  const record = { id: 'proof-1', testId: 'authorization-review', stage: 'non-mutating', status: 'completed',
    clusterId: cluster, context: evidence.target.context, namespace: 'payments', subject,
    predicate: 'can-list-secrets', value: true, completedAt: diagnosisTimestamp, synthetic: true,
    authenticatedSubject: { username: 'auditor' }, authenticatedSubjectAfter: { username: 'auditor' },
    request: { group: '', resource: 'secrets', verb: 'list', namespace: 'payments' },
    response: { allowed: true, denied: false, evaluationErrorPresent: false },
    method: 'SelfSubjectAccessReview', commands: [
      { file: 'kubectl', args: ['--context', evidence.target.context, 'auth', 'whoami', '--output=json'] },
      { file: 'kubectl', args: ['--context', evidence.target.context, 'create', '--raw=/apis/authorization.k8s.io/v1/selfsubjectaccessreviews', '-f', '-'] }] };
  const validated = claim({ subject, predicate: 'can-list-secrets', tier: 'validated-behavior', validationIds: [record.id] });
  assert.equal(reconcile([validated], { ...settings, validations: [record] }).findings[0].evidenceTier, 'validated-behavior');
  const wrongSubject = reconcile([validated], { ...settings, validations: [{ ...record, subject: `${subject}-other` }] }).findings[0];
  assert.equal(wrongSubject.evidenceTier, 'configured-exposure');
  const wrongContext = reconcile([validated], { ...settings, validations: [{ ...record, context: 'other-context' }] }).findings[0];
  assert.equal(wrongContext.evidenceTier, 'configured-exposure');
  const error = reconcile([validated], { ...settings, validations: [{ ...record, status: 'error' }] }).findings[0];
  assert.equal(error.evidenceTier, 'configured-exposure');
  const changedActor = reconcile([validated], { ...settings, validations: [{ ...record, authenticatedSubjectAfter: { username: 'other-actor' } }] }).findings[0];
  assert.equal(changedActor.evidenceTier, 'configured-exposure');
});

test('an authorization review cannot validate a different semantic condition even when the receipt says it does', async () => {
  const { reconcile } = await reconcileModule();
  const { claim, settings, evidence, cluster, subject } = fixture();
  const record = { id: 'proof-1', testId: 'authorization-review', stage: 'non-mutating', status: 'completed',
    clusterId: cluster, context: evidence.target.context, namespace: 'payments', subject, predicate: 'container-privileged',
    value: true, completedAt: diagnosisTimestamp, method: 'SelfSubjectAccessReview', commands: [] };
  assert.equal(reconcile([claim({ tier: 'validated-behavior', validationIds: [record.id] })],
    { ...settings, validations: [record] }).findings[0].evidenceTier, 'configured-exposure');
});

test('namespace and configuration summaries are derived views over reconciled findings, not duplicate scoring engines', async () => {
  const { reconcile } = await reconcileModule();
  const { claim, settings } = fixture();
  const result = reconcile([claim(), claim({ strategy: 'configuration' })], settings);
  const namespace = result.views.namespaces.find((item) => item.id === 'payments');
  const area = result.views.areas.find((item) => item.id === 'security');
  assert.deepEqual(namespace.findingIds, [result.findings[0].id]);
  assert.deepEqual(area.findingIds, [result.findings[0].id]);
  assert.equal(namespace.highestRisk, result.findings[0].risk.score);
});

test('stale evidence lowers confidence and cannot serve as current validation, without discounting the risk score', async () => {
  const { reconcile } = await reconcileModule();
  const { claim, settings } = fixture();
  const current = reconcile([claim()], settings).findings[0];
  const stale = reconcile([claim()], { ...settings, now: new Date(Date.parse(diagnosisTimestamp) + 48 * 3_600_000) }).findings[0];
  assert.ok(stale.confidence.score < current.confidence.score);
  assert.equal(stale.risk.score, current.risk.score);
  assert.ok(stale.confidence.limitations.some((item) => /stale/i.test(item)));
});

test('reconciliation is deterministic, rejects unsupported strategy claims and does not mutate inputs', async () => {
  const { reconcile } = await reconcileModule();
  const { claim, settings } = fixture();
  const claims = [claim(), claim({ strategy: 'configuration' })];
  const before = structuredClone(claims);
  assert.deepEqual(reconcile(claims, settings), reconcile([...claims].reverse(), settings));
  assert.deepEqual(claims, before);
  assert.throws(() => reconcile([claim({ strategy: 'arbitrary-plugin' })], settings), /strategy/i);
});

test('unverified target provenance cannot support a plausible exploitability classification', async () => {
  const { reconcile } = await reconcileModule();
  const { claim, settings } = fixture();
  const source = settings.graph.sources.find((item) => item.id === claim().evidenceRefs[0]);
  source.bindingStatus = 'unverified';
  const finding = reconcile([claim({ tier: 'plausible-exploitability' })], settings).findings[0];
  assert.equal(finding.evidenceTier, 'configured-exposure');
  assert.ok(finding.confidence.limitations.some((item) => /unverified/i.test(item)));
});
