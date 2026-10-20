import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { main, parseArgs } from '../bin/aks-xray.mjs';
import { demoEvidence } from '../examples/demo.mjs';
import { assess } from '../src/engine.mjs';
import { prepareOutput, renderHtml, validateAssessment, verifyArtifacts, writeArtifacts } from '../src/report.mjs';
import { runCommand } from '../src/process.mjs';

async function temporary(t) {
  const directory = await mkdtemp(join(tmpdir(), 'aks-xray-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test('CLI parsing refuses typos, duplicate flags, implicit active opt-ins and missing values', () => {
  assert.throws(() => parseArgs(['collect', '--contex', 'x']), /not valid/);
  assert.throws(() => parseArgs(['collect', '--context', 'x', '--context', 'y']), /Duplicate/);
  assert.throws(() => parseArgs(['collect', '--authorize-active']), /not valid/);
  assert.throws(() => parseArgs(['active', '--authorize-active=false']), /does not accept/);
  assert.throws(() => parseArgs(['collect', '--context']), /needs a value/);
  assert.equal(parseArgs(['--help']).command, 'help');
  assert.equal(parseArgs(['catalog', '--categories=security']).options.categories, 'security');
});

test('native launcher preserves multiple selected categories', async () => {
  let response;
  if (process.platform === 'win32') {
    const path = fileURLToPath(new URL('../scripts/Invoke-AksXRay.ps1', import.meta.url));
    const script = `& '${path.replaceAll("'", "''")}' catalog --categories networking,storage`;
    response = await runCommand('pwsh', ['-NoLogo', '-NoProfile', '-NonInteractive',
      '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')]);
  } else {
    const path = fileURLToPath(new URL('../scripts/aks-xray.sh', import.meta.url));
    response = await runCommand('bash', [path, 'catalog', '--categories', 'networking,storage']);
  }
  assert.match(response.stdout, /10 controls/);
  assert.match(response.stdout, /NET-001/);
  assert.match(response.stdout, /ST-001/);
});

test('offline demo, integrity verification and reassessment produce complete persistent outputs', async (t) => {
  const root = await temporary(t);
  const output = join(root, 'demo');
  const logs = [];
  assert.equal(await main(['demo', '--output', output], { log: (line) => logs.push(line), error: assert.fail }), 0);
  assert.equal(await verifyArtifacts(output), 4);
  const assessment = JSON.parse(await readFile(join(output, 'assessment.json'), 'utf8'));
  assert.equal(assessment.synthetic, true);
  assert.ok(logs.some((line) => line.includes('SYNTHETIC')));
  assert.equal(await main(['assess', '--input', join(output, 'evidence.json'), '--categories', 'storage',
    '--output', join(root, 'storage')], { log: () => {}, error: assert.fail }), 0);
  const selected = JSON.parse(await readFile(join(root, 'storage', 'assessment.json'), 'utf8'));
  assert.ok(selected.results.every((result) => result.id.startsWith('ST-')));
  await assert.rejects(() => main(['demo', '--output', output]), /must be empty/);
});

test('standalone report inlines its dependencies and neutralizes script-closing payloads', async () => {
  const assessment = assess(demoEvidence());
  assessment.target.context = '</script><script>alert("untrusted")</script>';
  const html = await renderHtml(assessment);
  assert.ok(html.includes('--cp-accent'));
  assert.ok(html.includes('connect-src \'none\''));
  assert.ok(!html.includes('<!--XRAY_'));
  assert.ok(!html.includes('</script><script>alert'));
  assert.ok(html.includes('\\u003c/script\\u003e'));
  assert.ok(!/<script[^>]*\ssrc=/.test(html));
  assert.ok(!/<link[^>]*\shref=/.test(html));
});

test('checksum changes are detected and output creation never overwrites existing evidence', async (t) => {
  const root = await temporary(t);
  const output = await prepareOutput(join(root, 'result'));
  const evidence = demoEvidence();
  await writeArtifacts(output, { evidence, assessment: assess(evidence) });
  await writeFile(join(output, 'assessment.md'), 'tampered');
  await assert.rejects(() => verifyArtifacts(output), /Integrity mismatch/);
  await assert.rejects(() => prepareOutput(output), /must be empty/);
});

test('report validation rejects forged counts and omitted controls but permits JSON key reordering', () => {
  const report = assess(demoEvidence());
  report.summary = Object.fromEntries(Object.entries(report.summary).reverse());
  assert.equal(validateAssessment(report), report);
  const forged = structuredClone(report);
  forged.summary.counts.pass = 999;
  assert.throws(() => validateAssessment(forged), /summary/);
  const omitted = structuredClone(report);
  omitted.results.pop();
  assert.throws(() => validateAssessment(omitted), /missing controls/);
  const malformed = structuredClone(report);
  malformed.collection = 'not a collection';
  assert.throws(() => validateAssessment(malformed), /provenance/);
});
