import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeAssessment } from '../src/diagnosis/config.mjs';
import { diagnosisEvidence, diagnosisTimestamp } from '../examples/diagnosis-fixture.mjs';
import { syntheticResources } from '../src/active.mjs';

const planner = () => import('../src/diagnosis/planner.mjs');
const now = () => new Date(diagnosisTimestamp);
const runId = '60000000-0000-4000-8000-000000000001';
function assessment(overrides = {}) {
  return normalizeAssessment({
    strategies: ['validation'], stages: ['passive', 'non-mutating', 'intrusive'],
    approvals: {
      nonMutating: { approved: true, contexts: ['context-xray-demo'], namespaces: ['payments'],
        tests: ['authorization-review', 'admission-dry-run', 'intrusive-preflight'], expiresAt: '2026-10-23T12:00:00Z' },
      intrusive: { approved: true, contexts: ['context-xray-demo'], suites: ['security'], expiresAt: '2026-10-23T12:00:00Z' }
    }, ...overrides
  });
}

test('passive diagnosis does not schedule non-mutating or intrusive activity implicitly', async () => {
  const { planAssessment } = await planner();
  const options = normalizeAssessment({ strategies: ['graph', 'exposure'], stages: ['passive'] });
  const plan = planAssessment([diagnosisEvidence()], options, { now: now() });
  assert.ok(plan.actions.every((action) => action.stage === 'passive'));
  assert.ok(!plan.actions.some((action) => action.testId === 'security'));
});

test('requested validation stages remain blocked without separate stage approvals', async () => {
  const { planAssessment } = await planner();
  const options = normalizeAssessment({ strategies: ['validation'], stages: ['passive', 'non-mutating', 'intrusive'] });
  const plan = planAssessment([diagnosisEvidence()], options, { now: now() });
  assert.ok(plan.actions.filter((action) => action.stage !== 'passive').every((action) => action.status === 'blocked'));
  assert.ok(plan.actions.some((action) => action.reasons.some((reason) => /approval/i.test(reason))));
});

test('non-mutating reviews require exact approved context and namespace, not a wildcard or broad read-only flag', async () => {
  const { planAssessment } = await planner();
  const evidence = diagnosisEvidence();
  evidence.scope.namespaces = ['orders'];
  const plan = planAssessment([evidence], assessment(), { now: now() });
  const dryRun = plan.actions.find((action) => action.testId === 'admission-dry-run');
  assert.equal(dryRun.status, 'blocked');
  assert.ok(dryRun.reasons.some((reason) => /namespace/i.test(reason)));
});

test('expired approvals and unverified cross-plane identity block validation before a command is issued', async () => {
  const { planAssessment } = await planner();
  const evidence = diagnosisEvidence();
  let plan = planAssessment([evidence], assessment(), { now: new Date('2026-10-23T13:00:00Z') });
  assert.ok(plan.actions.filter((action) => action.stage !== 'passive').every((action) => action.status === 'blocked'));
  evidence.sources.context.data.server = 'https://wrong.example.invalid';
  plan = planAssessment([evidence], assessment(), { now: now() });
  assert.ok(plan.actions.filter((action) => action.stage !== 'passive').every((action) => action.status === 'blocked'));
});

test('intrusive approval is not proof of permission; an unknown or denied permission matrix blocks mutation', async () => {
  const { planAssessment } = await planner();
  const plan = planAssessment([diagnosisEvidence()], assessment(), { now: now() });
  const action = plan.actions.find((item) => item.stage === 'intrusive');
  assert.equal(action.status, 'blocked');
  assert.equal(action.permissionStatus, 'unknown');
  assert.ok(action.reasons.some((reason) => /permission/i.test(reason)));
});

test('a complete fresh permission matrix can release only its exact planned owned canary action', async () => {
  const { planAssessment, intrusiveRequirements } = await planner();
  const evidence = diagnosisEvidence();
  const options = assessment();
  const initial = planAssessment([evidence], options, { now: now() });
  const action = initial.actions.find((item) => item.stage === 'intrusive');
  const namespace = `aks-xray-${runId.slice(0, 18)}`;
  const record = {
    id: 'preflight', testId: 'intrusive-preflight', forActionId: action.id, stage: 'non-mutating',
    status: 'completed', clusterId: action.clusterId, context: action.context, namespace, runId,
    completedAt: diagnosisTimestamp, subject: 'auditor',
    checks: intrusiveRequirements('security', namespace).map((request) => ({ request, allowed: true, evaluationErrorPresent: false }))
  };
  let plan = planAssessment([evidence], options, { now: now(), records: [record] });
  assert.equal(plan.actions.find((item) => item.id === action.id).status, 'ready');
  record.checks[0].allowed = false;
  plan = planAssessment([evidence], options, { now: now(), records: [record] });
  assert.equal(plan.actions.find((item) => item.id === action.id).status, 'blocked');
  assert.equal(plan.actions.find((item) => item.id === action.id).permissionStatus, 'denied');
  record.checks.pop();
  assert.equal(planAssessment([evidence], options, { now: now(), records: [record] })
    .actions.find((item) => item.id === action.id).status, 'blocked');
});

test('port-forward preflight uses the actual generated Service name rather than a guessed resource', async () => {
  const { intrusiveRequirements } = await planner();
  const namespace = `aks-xray-${runId.slice(0, 18)}`;
  const service = syntheticResources(namespace, runId).items.find((item) => item.kind === 'Service');
  const permission = intrusiveRequirements('end-to-end', namespace).find((item) => item.resource === 'services' && item.verb === 'get');
  assert.equal(permission.name, service.metadata.name);
});
