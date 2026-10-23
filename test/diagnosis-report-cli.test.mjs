import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main } from '../bin/aks-xray.mjs';
import { diagnose } from '../src/diagnosis/engine.mjs';
import { normalizeAssessment } from '../src/diagnosis/config.mjs';
import { verifyArtifacts } from '../src/report.mjs';
import { demoRaw } from '../examples/demo.mjs';
import { diagnosisConfig, diagnosisEvidence, diagnosisSubscriptions, diagnosisTenant, diagnosisTimestamp } from '../examples/diagnosis-fixture.mjs';
import { CommandError } from '../src/process.mjs';

const reports = () => import('../src/diagnosis/report.mjs');
async function temporary(t) {
  const directory = await mkdtemp(join(tmpdir(), 'aks-xray-diagnosis-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}
function sample() {
  return diagnose([diagnosisEvidence()], { tenant: diagnosisTenant, subscriptions: diagnosisSubscriptions,
    assessment: normalizeAssessment({ strategies: ['graph', 'exposure', 'attack-paths'], stages: ['passive'] }),
    now: new Date(diagnosisTimestamp) });
}

test('diagnosis HTML is graph/risk-first, standalone and safe for HTML-like inventory labels', async () => {
  const { renderDiagnosisHtml, renderDiagnosisMarkdown } = await reports();
  const value = sample();
  value.graph.nodes[0].name = '</script><script>UNTRUSTED_LABEL</script>';
  const html = await renderDiagnosisHtml(value);
  assert.match(html, /AKS workload diagnosis/);
  for (const id of ['risk-overview', 'attack-paths', 'graph-explorer', 'strategy-filter', 'evidence-tier-filter', 'stage-plan', 'namespace-view']) {
    assert.ok(html.includes(`id="${id}"`), id);
  }
  assert.ok(html.includes('--cp-accent'));
  assert.ok(html.includes('connect-src \'none\''));
  assert.ok(!html.includes('</script><script>UNTRUSTED_LABEL'));
  assert.ok(!/<script[^>]*\ssrc=/.test(html));
  assert.ok(!/<link[^>]*\shref=/.test(html));
  const markdown = renderDiagnosisMarkdown(value);
  assert.match(markdown, /## Reconciled risk findings/);
  assert.match(markdown, /## Attack hypotheses and prerequisites/);
  assert.match(markdown, /## Permission-aware stage plan/);
  assert.match(markdown, /Confidence/);
});

test('new synthetic CLI mode produces portable diagnosis artifacts without invoking live commands', async (t) => {
  const root = await temporary(t);
  const directory = join(root, 'demo');
  const logs = [];
  const result = await main(['demo', '--assessment-strategies', 'graph,exposure,attack-paths,validation', '--output', directory], {
    log: (line) => logs.push(line), error: assert.fail, runner: assert.fail
  });
  assert.equal(result, 0);
  const diagnosis = JSON.parse(await readFile(join(directory, 'diagnosis.json'), 'utf8'));
  assert.equal(diagnosis.synthetic, true);
  assert.equal(diagnosis.schemaVersion, '2.0');
  assert.ok(diagnosis.findings.some((finding) => finding.evidenceTier === 'configured-exposure'));
  assert.ok(diagnosis.findings.some((finding) => finding.evidenceTier === 'plausible-exploitability'));
  assert.ok(diagnosis.findings.some((finding) => finding.evidenceTier === 'validated-behavior'));
  assert.equal(await verifyArtifacts(directory), 7);
  assert.ok(logs.some((line) => /SYNTHETIC/.test(line)));
});

test('offline reconciliation selects a different single strategy from saved evidence without live collection', async (t) => {
  const { writeDiagnosisWorkspace } = await reports();
  const root = await temporary(t);
  const initial = join(root, 'initial');
  const evidence = diagnosisEvidence();
  const diagnosis = sample();
  await writeDiagnosisWorkspace(initial, [evidence], diagnosis);
  const output = join(root, 'configuration-only');
  await main(['diagnose', '--input', join(initial, 'diagnosis-evidence.json'),
    '--assessment-strategies', 'configuration', '--output', output], { log: () => {}, error: assert.fail, runner: assert.fail });
  const result = JSON.parse(await readFile(join(output, 'diagnosis.json'), 'utf8'));
  assert.deepEqual(result.selection.strategies, ['configuration']);
  assert.equal(result.configurationAssessments.length, 1);
  assert.ok(result.findings.every((finding) => finding.strategies.every((id) => id === 'configuration')));
});

test('live graph-only audit uses the diagnosis engine and does not create an implicit configuration assessment', async (t) => {
  const root = await temporary(t);
  const value = diagnosisConfig(['graph']);
  value.strategies = ['azure'];
  const config = join(root, 'scope.json');
  await writeFile(config, JSON.stringify(value));
  const calls = [];
  const runner = async (file, args) => {
    calls.push({ file, args });
    assert.equal(file, 'az');
    return { stdout: JSON.stringify(args[0] === 'account'
      ? { id: args[args.indexOf('--subscription') + 1], tenantId: diagnosisTenant, state: 'Enabled' } : demoRaw().cluster) };
  };
  const output = join(root, 'audit');
  assert.equal(await main(['audit', '--config', config, '--output', output], { runner, log: () => {}, error: () => {} }), 0);
  const result = JSON.parse(await readFile(join(output, 'diagnosis.json'), 'utf8'));
  assert.deepEqual(result.selection.strategies, ['graph']);
  assert.equal(result.configurationAssessments.length, 0);
  assert.ok(result.graph.nodes.length > 0);
  await assert.rejects(() => stat(join(output, 'cluster-001', 'assessment.json')), (error) => error.code === 'ENOENT');
  assert.ok(!calls.some(({ file }) => file === 'kubectl'));
});

test('saved diagnosis rendering validates scores without re-running any assessment commands', async (t) => {
  const root = await temporary(t);
  const input = join(root, 'diagnosis.json');
  await writeFile(input, JSON.stringify(sample()));
  const output = join(root, 'rendered');
  assert.equal(await main(['report', '--input', input, '--output', output], { runner: assert.fail, log: () => {}, error: assert.fail }), 0);
  assert.match(await readFile(join(output, 'report.html'), 'utf8'), /AKS workload diagnosis/);
});

test('portable input rejects path traversal, absolute references and altered evidence hashes', async (t) => {
  const { readDiagnosisInput, writeDiagnosisWorkspace } = await reports();
  const root = await temporary(t);
  const output = join(root, 'dataset');
  await writeDiagnosisWorkspace(output, [diagnosisEvidence()], sample());
  const path = join(output, 'diagnosis-evidence.json');
  const manifest = JSON.parse(await readFile(path, 'utf8'));
  for (const reference of ['../private.json', '..\\private.json', 'C:\\private.json', '/private.json']) {
    const altered = structuredClone(manifest);
    altered.bundles[0].path = reference;
    await writeFile(path, JSON.stringify(altered));
    await assert.rejects(() => readDiagnosisInput(path), /path|reference|scope/i);
  }
  await writeFile(path, JSON.stringify(manifest));
  await writeFile(join(output, 'cluster-001', 'evidence.json'), '{"changed":true}');
  await assert.rejects(() => readDiagnosisInput(path), /integrity|checksum|hash/i);
});

test('denied Azure target discovery still persists an explicitly incomplete diagnosis and never runs validation', async (t) => {
  const root = await temporary(t);
  const config = join(root, 'scope.json');
  await writeFile(config, JSON.stringify(diagnosisConfig(['graph', 'exposure'])));
  const output = join(root, 'denied');
  let calls = 0;
  const result = await main(['audit', '--config', config, '--output', output], {
    log: () => {}, error: () => {}, runner: async () => {
      calls++;
      throw new CommandError('COMMAND_FAILED', 'Metadata denied.', { stderr: 'Forbidden NEVER_EXPORT', exitCode: 1 });
    }
  });
  assert.equal(result, 2);
  assert.equal(calls, 1);
  const diagnosis = JSON.parse(await readFile(join(output, 'diagnosis.json'), 'utf8'));
  assert.equal(diagnosis.summary.highestRisk, null);
  assert.ok(diagnosis.gaps.some((gap) => gap.code === 'TARGET_BINDING'));
  assert.ok(!JSON.stringify(diagnosis).includes('NEVER_EXPORT'));
});

test('offline strategy selection from a staged dataset cannot request or execute fresh validation', async (t) => {
  const { writeDiagnosisWorkspace } = await reports();
  const root = await temporary(t);
  const evidence = diagnosisEvidence();
  const staged = diagnose([evidence], { scenario: sample().scenario,
    assessment: normalizeAssessment({ strategies: ['validation'], stages: ['passive', 'non-mutating'] }),
    now: new Date(diagnosisTimestamp) });
  const initial = join(root, 'staged');
  await writeDiagnosisWorkspace(initial, [evidence], staged);
  const output = join(root, 'graph-only');
  assert.equal(await main(['diagnose', '--input', initial, '--assessment-strategies', 'graph', '--output', output], {
    runner: assert.fail, log: () => {}, error: assert.fail
  }), 0);
  const result = JSON.parse(await readFile(join(output, 'diagnosis.json'), 'utf8'));
  assert.deepEqual(result.selection.strategies, ['graph']);
  assert.deepEqual(result.selection.stages, ['passive']);
});
