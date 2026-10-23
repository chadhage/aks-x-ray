import test from 'node:test';
import assert from 'node:assert/strict';
import { assess } from '../src/engine.mjs';
import { normalizeAssessment } from '../src/diagnosis/config.mjs';
import { diagnosisEvidence, diagnosisSubscriptions, diagnosisTenant, diagnosisTimestamp } from '../examples/diagnosis-fixture.mjs';
import { diagnosisDemo } from '../examples/diagnosis-demo.mjs';

const engine = () => import('../src/diagnosis/engine.mjs');
const options = (strategies) => ({ tenant: diagnosisTenant, subscriptions: diagnosisSubscriptions,
  scenario: { name: 'Sensitive production', profile: 'production', businessCriticality: 'critical',
    dataSensitivity: 'restricted', applicationExposure: 'public', assumedCompromise: [] },
  assessment: normalizeAssessment({ strategies, stages: ['passive'] }), now: new Date(diagnosisTimestamp) });

test('graph-only diagnosis is a new engine path and never invokes the configuration evaluator', async () => {
  const { diagnose } = await engine();
  const result = diagnose([diagnosisEvidence()], { ...options(['graph']), configurationEvaluator: assert.fail });
  assert.equal(result.kind, 'aks-xray-diagnosis');
  assert.equal(result.schemaVersion, '2.0');
  assert.ok(result.graph.nodes.length > 10);
  assert.equal(result.configurationAssessments.length, 0);
  assert.equal(result.findings.length, 0);
  assert.equal(result.summary.highestRisk, null);
  assert.deepEqual(result.strategyResults.map((item) => item.id), ['graph']);
});

test('single and combined analysis strategies run only selected evaluators and retain their independent contributions', async () => {
  const { diagnose } = await engine();
  const evidence = diagnosisEvidence();
  const exposure = diagnose([evidence], { ...options(['exposure']), configurationEvaluator: assert.fail });
  assert.ok(exposure.findings.some((finding) => finding.predicate === 'public-entry'));
  assert.ok(!exposure.findings.some((finding) => finding.predicate === 'workload-to-kubernetes-secrets'));
  const combined = diagnose([evidence], { ...options(['exposure', 'attack-paths']), configurationEvaluator: assert.fail });
  assert.ok(combined.findings.some((finding) => finding.predicate === 'workload-to-kubernetes-secrets'));
  assert.deepEqual(combined.selection.strategies, ['exposure', 'attack-paths']);
  assert.ok(combined.findings.every((finding) => finding.strategies.every((id) => combined.selection.strategies.includes(id))));
});

test('configuration is an optional adapter and exact overlapping assertions reconcile with graph-based exposure claims', async () => {
  const { diagnose } = await engine();
  const evidence = diagnosisEvidence();
  for (const id of ['pods', 'deployments']) evidence.sources[id].data.items[0].pod.spec.containers[0].securityContext.privileged = true;
  let evaluated = 0;
  const result = diagnose([evidence], { ...options(['configuration', 'exposure']), configurationEvaluator: (...args) => { evaluated++; return assess(...args); } });
  assert.equal(evaluated, 1);
  assert.equal(result.configurationAssessments.length, 1);
  const overlapping = result.findings.find((finding) => finding.predicate === 'container-privileged');
  assert.ok(overlapping);
  assert.deepEqual(overlapping.strategies, ['configuration', 'exposure']);
  assert.equal(overlapping.contributions.length, 2);
  assert.ok(result.views.namespaces.some((view) => view.id === 'payments'));
});

test('diagnosis validation recomputes risk, confidence, evidence tiers and views instead of trusting saved scores', async () => {
  const { diagnose, validateDiagnosis } = await engine();
  const diagnosis = diagnose([diagnosisEvidence()], options(['exposure', 'attack-paths']));
  assert.equal(validateDiagnosis(JSON.parse(JSON.stringify(diagnosis))).kind, 'aks-xray-diagnosis');
  for (const mutate of [
    (value) => { value.findings[0].risk.score = 1000; },
    (value) => { value.findings[0].confidence.score = 1000; },
    (value) => { value.findings[0].evidenceTier = 'validated-behavior'; },
    (value) => { value.views.namespaces[0].findingIds = []; },
    (value) => { value.graph.edges[0].to = 'nonexistent-node'; }
  ]) {
    const value = structuredClone(diagnosis);
    mutate(value);
    assert.throws(() => validateDiagnosis(value), /diagnosis|risk|confidence|tier|graph|view/i);
  }
});

test('graph limits produce persistent partial diagnosis with blocked strategies, not an implicit checklist fallback', async () => {
  const { diagnose, diagnosisExitCode } = await engine();
  const settings = options(['graph', 'exposure']);
  settings.assessment.maxGraphNodes = 3;
  const result = diagnose([diagnosisEvidence()], { ...settings, configurationEvaluator: assert.fail });
  assert.ok(result.gaps.some((gap) => gap.code === 'GRAPH_LIMIT'));
  assert.equal(result.summary.highestRisk, null);
  assert.equal(diagnosisExitCode(result), 2);
  assert.ok(result.strategyResults.every((strategy) => strategy.status === 'blocked'));
});

test('a deterministic diagnosis preserves provenance and namespace views across input ordering', async () => {
  const { diagnose } = await engine();
  const first = diagnosisEvidence();
  const second = diagnosisEvidence({ cluster: 'second', subscription: diagnosisSubscriptions[1] });
  const before = diagnose([first, second], options(['graph', 'exposure', 'attack-paths']));
  assert.deepEqual(diagnose([second, first], options(['graph', 'exposure', 'attack-paths'])), before);
});

test('validated identities and scoped permission observations enter the graph without validating an entire attack path', async () => {
  const { diagnose } = await engine();
  const input = diagnosisDemo(['graph', 'attack-paths', 'validation']);
  const result = diagnose(input.bundles, input);
  const receipt = input.validations[0];
  assert.ok(result.graph.nodes.some((node) => node.id === receipt.subject));
  assert.ok(result.graph.edges.some((edge) => edge.from === receipt.subject && edge.relationship === 'validated-permission'));
  assert.ok(result.graph.sources.some((source) => source.sourceId === 'validation'));
  assert.ok(result.findings.filter((finding) => finding.paths.length).every((finding) => finding.evidenceTier !== 'validated-behavior'));
});

test('validation graph enrichment obeys the same graph size limit as passive evidence', async () => {
  const { diagnose, diagnosisExitCode } = await engine();
  const input = diagnosisDemo(['graph', 'validation']);
  const passive = diagnose(input.bundles, { ...input, validations: [] });
  input.assessment.maxGraphNodes = passive.graph.nodes.length;
  const result = diagnose(input.bundles, input);
  assert.ok(result.graph.nodes.length <= input.assessment.maxGraphNodes);
  assert.ok(result.gaps.some((gap) => gap.code === 'GRAPH_LIMIT'));
  assert.equal(diagnosisExitCode(result), 2);
});
