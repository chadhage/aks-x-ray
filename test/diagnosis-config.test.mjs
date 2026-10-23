import test from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs } from '../bin/aks-xray.mjs';
import { buildAuditPlan, validateAuditConfig } from '../src/audit.mjs';
import { diagnosisConfig } from '../examples/diagnosis-fixture.mjs';

const config = (strategies) => {
  const value = diagnosisConfig(strategies);
  delete value.targets[0].tenant;
  return value;
};

test('CLI exposes independently selectable assessment strategies and offline diagnosis', () => {
  assert.deepEqual(parseArgs(['audit', '--config', 'scope.json', '--assessment-strategies', 'exposure,attack-paths']).options['assessment-strategies'], 'exposure,attack-paths');
  assert.equal(parseArgs(['diagnose', '--input', 'evidence.json', '--assessment-strategies', 'graph']).command, 'diagnose');
  assert.equal(parseArgs(['demo', '--assessment-strategies', 'graph,exposure,attack-paths']).command, 'demo');
});

test('analysis strategy selection is separate from collection permission and never implies validation approval', () => {
  const value = config(['attack-paths']);
  const before = structuredClone(value);
  const normalized = validateAuditConfig(value);
  assert.deepEqual(value, before);
  assert.deepEqual(normalized.assessment.strategies, ['attack-paths']);
  assert.deepEqual(normalized.scope.assessmentStrategies, ['attack-paths']);
  assert.deepEqual(normalized.scope.strategies, value.strategies);
  assert.deepEqual(normalized.assessment.stages, ['passive']);
  assert.equal(normalized.assessment.approvals.nonMutating.approved, false);
  assert.equal(normalized.assessment.approvals.intrusive.approved, false);
});

test('a single graph strategy is valid without requiring the configuration evaluator', () => {
  const plan = buildAuditPlan(config(['graph']));
  assert.deepEqual(plan.assessment.strategies, ['graph']);
  assert.ok(plan.assessment.dependencies.includes('resource-identity-graph'));
  assert.ok(!plan.assessment.dependencies.includes('configuration-evaluator'));
  assert.ok(!plan.targets[0].sources.some((source) => source.id === 'maintenance'));
});

test('assessment dry-run describes requested validation stages without issuing them or pretending approval', () => {
  const value = config(['validation']);
  value.assessment.stages = ['passive', 'non-mutating', 'intrusive'];
  const plan = buildAuditPlan(value);
  assert.ok(plan.assessment.approvalRequirements.some((item) => item.stage === 'intrusive' && item.approved === false));
  assert.equal(plan.readOnly, false);
});

const invalid = [
  ['unknown assessment strategy', (v) => { v.assessment.strategies = ['exploit-anything']; }, /assessment.*strateg/i],
  ['duplicate assessment strategies', (v) => { v.assessment.strategies = ['graph', 'graph']; }, /duplicate/i],
  ['empty assessment strategy selection', (v) => { v.assessment.strategies = []; }, /strateg/i],
  ['null assessment options', (v) => { v.assessment = null; }, /assessment/i],
  ['null stage selection', (v) => { v.assessment.stages = null; }, /stage/i],
  ['null approval options', (v) => { v.assessment.approvals = null; }, /approval/i],
  ['unknown option', (v) => { v.assessment.stratgeies = ['graph']; }, /Unknown/],
  ['unknown validation stage', (v) => { v.assessment.stages = ['passive', 'destructive']; }, /stage/i],
  ['implicit collection stage', (v) => { v.assessment.stages = ['intrusive']; }, /passive/i],
  ['validation stages without selected strategy', (v) => { v.assessment.strategies = ['graph']; v.assessment.stages = ['passive', 'non-mutating']; }, /validation.*strateg/i],
  ['string approval', (v) => { v.assessment.approvals = { intrusive: { approved: 'true' } }; }, /approved|approval/i],
  ['approved intrusive stage without exact contexts', (v) => { v.assessment.approvals = { intrusive: { approved: true, contexts: [], suites: ['security'], expiresAt: '2026-10-24T12:00:00Z' } }; }, /context/i],
  ['nonexistent approval calendar date', (v) => { v.assessment.approvals = { intrusive: { approved: true,
    contexts: ['context-xray-demo'], suites: ['security'], expiresAt: '2027-02-30T12:00:00Z' } }; }, /expiresAt|timestamp/i],
  ['unbounded path enumeration', (v) => { v.assessment.maxPaths = 0; }, /maxPaths/],
  ['invalid evidence age', (v) => { v.assessment.maxEvidenceAgeHours = -1; }, /maxEvidenceAgeHours/],
  ['unknown business criticality', (v) => { v.scenario.businessCriticality = 'guess'; }, /businessCriticality/],
  ['null sensitivity', (v) => { v.scenario.dataSensitivity = null; }, /dataSensitivity|scenario/i],
  ['implicit assumed compromise', (v) => { v.scenario.assumedCompromise = true; }, /assumedCompromise/]
];
for (const [label, mutate, expected] of invalid) {
  test(`diagnosis config rejects ${label}`, () => {
    const value = config(['validation']);
    mutate(value);
    assert.throws(() => validateAuditConfig(value), expected);
  });
}
