import test from 'node:test';
import assert from 'node:assert/strict';
import { demoEvidence } from '../examples/demo.mjs';
import { assess, exitCode } from '../src/engine.mjs';
import { controls, validateCatalog } from '../src/catalog.mjs';
import { defaultScope, validateEvidence } from '../src/evidence.mjs';
import { projectSource } from '../src/projection.mjs';
import { requiredSources } from '../src/collector.mjs';

const finding = (evidence, id) => assess(evidence).results.find((result) => result.id === id);

test('catalogue is exclusively first-party and all controls are executable or explicit reviews', () => {
  assert.ok(validateCatalog().controls >= 65);
  for (const platform of ['cloud', 'local']) {
    const report = assess(demoEvidence(platform));
    assert.equal(report.results.length, controls.length);
    assert.deepEqual(report.results.filter((result) => result.status === 'error'), []);
    assert.equal(report.target.binding.status, 'verified');
    assert.equal(report.synthetic, true);
    assert.ok(report.summary.evidenceCoveragePercent < 100);
  }
});

test('permission failure is unknown, never a false pass', () => {
  const evidence = demoEvidence();
  evidence.sources.pods = { status: 'error', collectedAt: evidence.collectedAt,
    error: { code: 'FORBIDDEN', message: 'Insufficient API permissions.' } };
  const report = assess(evidence);
  assert.equal(report.results.find((result) => result.id === 'SEC-001').status, 'unknown');
  assert.equal(exitCode(report), 2);
});

test('missing API booleans are unknown rather than success-shaped defaults', () => {
  const evidence = demoEvidence();
  delete evidence.sources.cluster.data.disableLocalAccounts;
  assert.equal(finding(evidence, 'ID-003').status, 'unknown');
});

test('empty resource sets are not positive compliance evidence', () => {
  const evidence = demoEvidence();
  evidence.sources.pvcs.data.items = [];
  evidence.sources.nodes.data.items = [];
  assert.equal(finding(evidence, 'ST-001').status, 'notApplicable');
  assert.equal(finding(evidence, 'ND-001').status, 'fail');
});

test('target mismatch blocks all other conclusions and disables alignment', () => {
  const evidence = demoEvidence();
  evidence.sources.context.data.server = 'https://different.example.invalid';
  const report = assess(evidence);
  assert.equal(report.results.find((result) => result.id === 'CP-001').status, 'fail');
  assert.equal(report.results.find((result) => result.id === 'ID-001').status, 'unknown');
  assert.equal(report.summary.alignmentPercent, null);
  assert.equal(exitCode(report), 2);
});

test('Local does not inherit cloud-only controls or require cloud metadata shapes', () => {
  const evidence = demoEvidence('local');
  assert.equal(finding(evidence, 'ID-001').status, 'notApplicable');
  assert.equal(finding(evidence, 'LOC-002').status, 'pass');
  evidence.sources.cluster.data.controlPlane.count = 1;
  assert.equal(finding(evidence, 'LOC-002').status, 'fail');
  assert.ok(!requiredSources(evidence.scope, 'local').includes('nodepools'));
});

test('category scope only selects relevant checks and collection dependencies', () => {
  const scope = defaultScope({ categories: ['storage'] });
  const evidence = demoEvidence('cloud', scope);
  assert.ok(assess(evidence).results.every((result) => result.id.startsWith('ST-')));
  assert.ok(!requiredSources(scope, 'cloud').includes('pods'));
  assert.throws(() => defaultScope({ categories: ['typo'] }), /Unknown category/);
});

test('development baseline does not silently claim production availability', () => {
  const evidence = demoEvidence('cloud', defaultScope({ profile: 'development' }));
  assert.equal(finding(evidence, 'REL-001').status, 'notApplicable');
});

test('resource conflicts, probe declarations and PDB drain blockers are evaluated', () => {
  const evidence = demoEvidence();
  assert.equal(finding(evidence, 'WK-004').status, 'fail');
  assert.equal(finding(evidence, 'WK-003').status, 'pass');
  assert.equal(finding(evidence, 'REL-005').status, 'fail');
  evidence.sources.pdbs.data.items[0].spec.minAvailable = '50%';
  assert.equal(finding(evidence, 'REL-005').status, 'pass');
});

test('explicit Windows containers are not scored using Linux-only restrictions', () => {
  const evidence = demoEvidence();
  for (const id of ['deployments', 'pods']) {
    const spec = evidence.sources[id].data.items[0].pod.spec;
    spec.osName = 'windows';
    spec.nodeSelector = { 'kubernetes.io/os': 'windows' };
    spec.containers[0].securityContext = {};
  }
  assert.equal(finding(evidence, 'SEC-002').status, 'notApplicable');
  assert.equal(finding(evidence, 'SEC-003').status, 'notApplicable');
});

test('container UID zero overrides a pod non-root declaration', () => {
  const evidence = demoEvidence();
  evidence.sources.deployments.data.items[0].pod.spec.containers[0].securityContext.runAsUser = 0;
  assert.equal(finding(evidence, 'SEC-003').status, 'fail');
});

test('projections omit credentials, container commands, annotations and event messages', () => {
  const raw = { kind: 'Pod', metadata: { name: 'sensitive', namespace: 'payments',
    annotations: { token: 'DO_NOT_EXPORT' } }, spec: { containers: [{ name: 'app', image: 'app:v1',
    env: [{ name: 'PASSWORD', value: 'DO_NOT_EXPORT' }], command: ['DO_NOT_EXPORT'],
    args: ['DO_NOT_EXPORT'], readinessProbe: { httpGet: { httpHeaders: [{ value: 'DO_NOT_EXPORT' }] } } }],
  volumes: [{ name: 'host', hostPath: { path: 'DO_NOT_EXPORT' } }] } };
  assert.ok(!JSON.stringify(projectSource('pods', { items: [raw] })).includes('DO_NOT_EXPORT'));
  assert.ok(!JSON.stringify(demoEvidence()).includes('This message is intentionally not exported.'));
  assert.throws(() => projectSource('pods', {}), /explicit resource list/);
});

test('invalid evidence shapes and unsupported revisions are explicit errors', () => {
  const evidence = demoEvidence();
  evidence.sources.pods.data = {};
  assert.throws(() => validateEvidence(evidence), /items array/);
  const version = demoEvidence();
  version.schemaVersion = '999';
  assert.throws(() => validateEvidence(version), /schemaVersion/);
});

test('active tests are explicitly not-run until authorized; manual controls never auto-pass', () => {
  const report = assess(demoEvidence());
  assert.equal(report.results.find((result) => result.id === 'ACT-001').status, 'notRun');
  assert.ok(report.results.filter((result) => controls.find((control) => control.id === result.id).mode === 'manual')
    .every((result) => ['review', 'notApplicable'].includes(result.status)));
});

test('severity gate is opt-in and distinct from collection failure', () => {
  const report = assess(demoEvidence());
  assert.equal(exitCode(report), 0);
  assert.equal(exitCode(report, 'high'), 1);
  assert.throws(() => exitCode(report, 'urgent'), /Invalid --fail-on/);
});
