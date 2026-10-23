import test from 'node:test';
import assert from 'node:assert/strict';
import { assess } from '../src/engine.mjs';
import { demoEvidence, demoTimestamp } from '../examples/demo.mjs';
import { defaultScope } from '../src/evidence.mjs';
import { renderHtml, renderMarkdown, validateAssessment } from '../src/report.mjs';

const finding = (report, id) => report.results.find((result) => result.id === id);
const scored = () => assess(demoEvidence(), { now: new Date(demoTimestamp) });

test('every configuration assertion has a bounded 1-100 score or an explicit unscored result', () => {
  const report = scored();
  assert.equal(finding(report, 'ID-001').score, 100);
  assert.equal(finding(report, 'WK-004').score, 1);
  assert.equal(finding(report, 'ID-005').score, null);
  assert.equal(finding(report, 'ACT-001').score, null);
  assert.ok(report.results.every((result) => result.score === null
    || Number.isInteger(result.score) && result.score >= 1 && result.score <= 100));
});

test('per-control mixed observations use the exact 1 + 99 * adherence fraction rubric', () => {
  const evidence = demoEvidence();
  const unsafe = structuredClone(evidence.sources.pods.data.items[0]);
  unsafe.metadata.name = 'unsafe-pod';
  unsafe.pod.spec.containers[0].securityContext.privileged = true;
  evidence.sources.pods.data.items.push(unsafe);
  const result = finding(assess(evidence), 'SEC-001');
  assert.equal(result.observed.checked, 3);
  assert.equal(result.observed.deviations.count, 1);
  assert.equal(result.score, 67);
});

test('unknown, partial, and unbound observations never receive reassuring numeric scores', () => {
  const missing = demoEvidence();
  delete missing.sources.cluster.data.disableLocalAccounts;
  assert.equal(finding(assess(missing), 'ID-003').score, null);
  const partial = demoEvidence();
  delete partial.sources.pods.data.items[0].pod.spec.nodeSelector;
  delete partial.sources.pods.data.items[0].pod.spec.nodeName;
  partial.sources.deployments.data.items[0].pod.spec.containers[0].securityContext.runAsUser = 0;
  const result = finding(assess(partial), 'SEC-003');
  assert.equal(result.incomplete, true);
  assert.equal(result.score, null);
  const mismatch = demoEvidence();
  mismatch.sources.context.data.server = 'https://different.example.invalid';
  const report = assess(mismatch);
  assert.equal(report.ratings.overall.score, null);
  assert.ok(report.results.every((item) => item.score === null));
});

test('ratings cover configuration areas and all five WAF pillars, and always expose evidence coverage', () => {
  const report = scored();
  assert.equal(report.ratings.methodology.projectDefined, true);
  assert.equal(report.ratings.areas.length, report.scope.categories.length);
  assert.deepEqual(report.ratings.pillars.map(({ id }) => id), [
    'reliability', 'security', 'cost-optimization', 'operational-excellence', 'performance-efficiency'
  ]);
  assert.ok(report.ratings.overall.score >= 1 && report.ratings.overall.score <= 100);
  assert.ok(report.ratings.overall.coveragePercent < 100);
  assert.ok(report.ratings.overall.unscored > 0);
  assert.ok(report.ratings.areas.every((area) => Array.isArray(area.controlIds)));
});

test('namespace ratings reevaluate each namespace rather than repeating a cluster-wide failure everywhere', () => {
  const evidence = demoEvidence();
  evidence.sources.namespaces.data.items.push({ kind: 'Namespace', metadata: { name: 'orders', labels: {} } });
  const unsafe = structuredClone(evidence.sources.pods.data.items[0]);
  unsafe.metadata.name = 'orders-pod';
  unsafe.metadata.namespace = 'orders';
  unsafe.pod.spec.containers[0].securityContext.privileged = true;
  evidence.sources.pods.data.items.push(unsafe);
  const report = assess(evidence);
  assert.deepEqual(report.namespaceResults.map(({ namespace }) => namespace), ['orders', 'payments']);
  const payments = report.namespaceResults.find((entry) => entry.namespace === 'payments');
  const orders = report.namespaceResults.find((entry) => entry.namespace === 'orders');
  assert.equal(finding(payments, 'SEC-001').score, 100);
  assert.equal(finding(orders, 'SEC-001').score, 1);
  assert.ok(!payments.results.some((result) => result.id === 'CP-002'));
  assert.equal(report.ratings.namespaces.length, 2);
});

test('namespace selections and system exclusions also apply to scored summaries', () => {
  const scope = defaultScope({ namespaces: ['payments'] });
  const evidence = demoEvidence('cloud', scope);
  evidence.sources.pods.data.items.push({ ...structuredClone(evidence.sources.pods.data.items[0]),
    metadata: { name: 'system-pod', namespace: 'kube-system' } });
  const report = assess(evidence);
  assert.deepEqual(report.ratings.namespaces.map(({ id }) => id), ['payments']);
});

test('namespace score groups are deterministic even when API resource order changes', () => {
  const evidence = demoEvidence();
  evidence.sources.namespaces.data.items.push({ kind: 'Namespace', metadata: { name: 'orders', labels: {} } });
  const first = assess(evidence, { now: new Date(demoTimestamp) });
  assert.ok(first.ratings && Array.isArray(first.namespaceResults));
  evidence.sources.namespaces.data.items.reverse();
  const second = assess(evidence, { now: new Date(demoTimestamp) });
  assert.deepEqual(first.ratings, second.ratings);
  assert.deepEqual(first.namespaceResults, second.namespaceResults);
});

test('report validators recompute ratings and reject forged individual, area and namespace scores', () => {
  const report = scored();
  assert.equal(validateAssessment(report), report);
  for (const mutate of [
    (value) => { finding(value, 'ID-001').score = 99; },
    (value) => { value.ratings.overall.score = 999; },
    (value) => { value.ratings.areas[0].score = 999; },
    (value) => { value.ratings.namespaces[0].score = 999; },
    (value) => { value.namespaceResults[0].results.pop(); }
  ]) {
    const copy = structuredClone(report);
    mutate(copy);
    assert.throws(() => validateAssessment(copy), /scor|rating|namespace/i);
  }
});

test('Markdown and offline HTML expose scenario, area, WAF, namespace and per-control scores', async () => {
  const evidence = demoEvidence('cloud', defaultScope({ scenario: {
    name: 'Private production', profile: 'production', apiAccess: 'private', minimumReplicas: 3, minimumZones: 3
  } }));
  const report = assess(evidence);
  const markdown = renderMarkdown(report);
  for (const heading of ['## Configuration-area scores', '## Azure Well-Architected pillars', '## Namespace scores']) {
    assert.ok(markdown.includes(heading), heading);
  }
  assert.match(markdown, /Private production/);
  assert.match(markdown, /Score \(1-100\)/);
  assert.match(markdown, /project-defined/i);
  const html = await renderHtml(report);
  assert.match(html, /id="rating-overview"/);
  assert.match(html, /id="namespace-filter"/);
  assert.match(html, /id="namespace-ratings"/);
  assert.ok(!/<script[^>]*\ssrc=/.test(html));
  assert.ok(html.includes('connect-src \'none\''));
});

test('scoring runtime rejects inconsistent observation counts and uses stable severity weights', async () => {
  const { ratingRuntime } = await import('../src/scoring.mjs');
  const runtime = ratingRuntime([
    { id: 'A', category: 'sample', severity: 'high', requires: [] },
    { id: 'B', category: 'sample', severity: 'low', requires: [] }
  ], [{ id: 'sample', title: 'Sample', pillars: ['security'] }], []);
  const result = (id, status) => ({ id, status, incomplete: false });
  assert.equal(runtime.score(result('A', 'pass'), 'verified'), 100);
  assert.equal(runtime.score(result('A', 'fail'), 'verified'), 1);
  assert.equal(runtime.group([result('A', 'fail'), result('B', 'pass')], 'verified').score, 18);
  assert.throws(() => runtime.score({ ...result('A', 'fail'),
    observed: { checked: 2, deviations: { count: 3 } } }, 'verified'), /observation/i);
});

test('mutating a returned rating methodology cannot change subsequent scores or contaminate other runs', () => {
  const report = scored();
  const expected = report.ratings.overall.score;
  report.ratings.methodology.weights.high = 999;
  assert.equal(scored().ratings.overall.score, expected);
});
